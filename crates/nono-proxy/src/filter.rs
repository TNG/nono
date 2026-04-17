//! Async host filtering wrapping the library's [`HostFilter`](nono::HostFilter).
//!
//! Performs DNS resolution via `tokio::net::lookup_host()`, checks resolved
//! IPs against the link-local range (cloud metadata SSRF protection), and
//! validates the hostname against the cloud metadata deny list and allowlist.

use crate::error::Result;
use crate::interactive::{InteractivePolicy, PermanentDecision};
use nono::net_filter::{FilterResult, HostFilter};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tracing::{debug, info};

/// Result of a filter check including resolved socket addresses.
///
/// When the filter allows a host, `resolved_addrs` contains the DNS-resolved
/// addresses. Callers MUST connect to these addresses (not re-resolve the
/// hostname) to prevent DNS rebinding TOCTOU attacks.
pub struct CheckResult {
    /// The filter decision
    pub result: FilterResult,
    /// DNS-resolved addresses (empty if denied or DNS failed)
    pub resolved_addrs: Vec<SocketAddr>,
}

/// Async wrapper around `HostFilter` that performs DNS resolution.
///
/// When `interactive` is set, hosts returning [`FilterResult::DenyNotAllowed`]
/// are escalated to an interactive prompt. Cloud-metadata denies and
/// link-local IP blocks remain absolute and are NEVER promptable.
#[derive(Debug, Clone)]
pub struct ProxyFilter {
    inner: HostFilter,
    interactive: Option<Arc<InteractivePolicy>>,
    /// Lowercased explicit allowlist hosts. Used by interactive mode to
    /// short-circuit the prompt for hosts the profile already trusts, even
    /// when the inner `HostFilter` was built in "allow-all" mode (empty
    /// allowlist). Entries starting with `*` are treated as suffix patterns.
    explicit_allow: Vec<String>,
}

impl ProxyFilter {
    /// Create a new proxy filter with the given allowed hosts.
    #[must_use]
    pub fn new(allowed_hosts: &[String]) -> Self {
        Self {
            inner: HostFilter::new(allowed_hosts),
            interactive: None,
            explicit_allow: allowed_hosts.iter().map(|h| h.to_lowercase()).collect(),
        }
    }

    /// Create a filter that allows all hosts (except cloud metadata).
    #[must_use]
    pub fn allow_all() -> Self {
        Self {
            inner: HostFilter::allow_all(),
            interactive: None,
            explicit_allow: Vec::new(),
        }
    }

    /// Attach an interactive policy evaluator. When set, the filter prompts
    /// the user for any host not in `explicit_allow` (on top of cloud
    /// metadata denies and link-local IP blocks, which remain absolute).
    #[must_use]
    pub fn with_interactive(mut self, policy: Arc<InteractivePolicy>) -> Self {
        self.interactive = Some(policy);
        self
    }

    /// Whether interactive prompting is active.
    #[must_use]
    pub fn has_interactive(&self) -> bool {
        self.interactive.is_some()
    }

    /// Check whether `host` matches the explicit allowlist (exact host or
    /// `*.suffix` pattern). Lowercase comparison.
    fn is_explicitly_allowed(&self, host: &str) -> bool {
        let lower = host.to_lowercase();
        for pattern in &self.explicit_allow {
            if let Some(suffix) = pattern.strip_prefix('*') {
                // `*.example.com` -> match exact `example.com` or any `*.example.com`.
                let base = suffix.trim_start_matches('.');
                if lower == base || lower.ends_with(&format!(".{}", base)) {
                    return true;
                }
            } else if lower == *pattern {
                return true;
            }
        }
        false
    }

    /// Check a host against the filter with async DNS resolution.
    ///
    /// Resolves the hostname to IP addresses, then checks all resolved IPs
    /// against the link-local deny range (cloud metadata SSRF protection).
    /// If any resolved IP is link-local, the request is blocked.
    ///
    /// On success, returns both the filter result and the resolved socket
    /// addresses. Callers MUST use `resolved_addrs` to connect to the upstream
    /// instead of re-resolving the hostname, eliminating the DNS rebinding
    /// TOCTOU window.
    pub async fn check_host(&self, host: &str, port: u16) -> Result<CheckResult> {
        // Resolve DNS
        let addr_str = format!("{}:{}", host, port);
        let resolved: Vec<SocketAddr> = match tokio::net::lookup_host(&addr_str).await {
            Ok(addrs) => addrs.collect(),
            Err(e) => {
                debug!("DNS resolution failed for {}: {}", host, e);
                // If DNS fails, we still check the hostname against deny list
                // (cloud metadata hostnames don't need DNS resolution to be blocked)
                Vec::new()
            }
        };

        let resolved_ips: Vec<IpAddr> = resolved.iter().map(|a| a.ip()).collect();
        let mut result = self.inner.check_host(host, &resolved_ips);
        debug!(
            "Filter check {}:{} → {:?} (interactive={}, explicit_allow_count={})",
            host,
            port,
            result,
            self.interactive.is_some(),
            self.explicit_allow.len()
        );

        // Interactive-mode escalation. Cloud-metadata and link-local denies
        // are absolute and must NEVER reach the prompt — those are handled
        // by preserving `result` unchanged when it isn't `Allow` or
        // `DenyNotAllowed`.
        if let Some(policy) = &self.interactive {
            let needs_prompt = match &result {
                // Unknown host: always prompt (classic "unknown domain" case).
                FilterResult::DenyNotAllowed { .. } => true,
                // Allow: prompt ONLY when the host isn't in the explicit
                // allowlist, because an empty allowlist in the inner filter
                // produces Allow for every host (allow-all mode). Without
                // this check, interactive mode would never trigger for
                // profiles that don't configure allow_domain.
                FilterResult::Allow => !self.is_explicitly_allowed(host),
                // Absolute denies (cloud metadata, link-local): never prompt.
                FilterResult::DenyHost { .. } | FilterResult::DenyLinkLocal { .. } => false,
            };
            if needs_prompt {
                match policy.decide(host, port).await {
                    Ok(decision) => {
                        if decision.is_allow() {
                            info!(
                                "Interactive policy allowed {}:{} (decision={:?})",
                                host, port, decision
                            );
                            result = FilterResult::Allow;
                        } else {
                            info!(
                                "Interactive policy denied {}:{} (decision={:?})",
                                host, port, decision
                            );
                            result = FilterResult::DenyNotAllowed {
                                host: host.to_string(),
                            };
                        }
                    }
                    Err(e) => {
                        debug!("Interactive policy lookup failed for {}: {}", host, e);
                    }
                }
            } else if matches!(result, FilterResult::Allow) {
                // Explicitly allowed host — still honour a stored permanent
                // deny so users can revoke previously trusted destinations.
                if let Some(PermanentDecision::Deny) = policy.stored_decision(host).await {
                    info!(
                        "Interactive policy overrides allowlist with stored deny for {}",
                        host
                    );
                    result = FilterResult::DenyNotAllowed {
                        host: host.to_string(),
                    };
                }
            }
        }

        // Only return resolved addrs on allow to prevent misuse
        let addrs = if result.is_allowed() {
            resolved
        } else {
            Vec::new()
        };

        Ok(CheckResult {
            result,
            resolved_addrs: addrs,
        })
    }

    /// Check a host with pre-resolved IPs (no DNS lookup).
    #[must_use]
    pub fn check_host_with_ips(&self, host: &str, resolved_ips: &[IpAddr]) -> FilterResult {
        self.inner.check_host(host, resolved_ips)
    }

    /// Number of allowed hosts configured.
    #[must_use]
    pub fn allowed_count(&self) -> usize {
        self.inner.allowed_count()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_proxy_filter_delegates_to_host_filter() {
        let filter = ProxyFilter::new(&["api.openai.com".to_string()]);
        let public_ip = vec![IpAddr::V4(Ipv4Addr::new(104, 18, 7, 96))];

        let result = filter.check_host_with_ips("api.openai.com", &public_ip);
        assert!(result.is_allowed());

        let result = filter.check_host_with_ips("evil.com", &public_ip);
        assert!(!result.is_allowed());
    }

    #[test]
    fn test_proxy_filter_allow_all() {
        let filter = ProxyFilter::allow_all();
        let public_ip = vec![IpAddr::V4(Ipv4Addr::new(104, 18, 7, 96))];
        let result = filter.check_host_with_ips("anything.com", &public_ip);
        assert!(result.is_allowed());
    }

    #[test]
    fn test_proxy_filter_allows_private_networks() {
        let filter = ProxyFilter::allow_all();
        let private_ip = vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))];
        let result = filter.check_host_with_ips("corp.internal", &private_ip);
        assert!(result.is_allowed());
    }

    #[test]
    fn test_proxy_filter_denies_link_local() {
        let filter = ProxyFilter::allow_all();
        let link_local = vec![IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))];
        let result = filter.check_host_with_ips("evil.com", &link_local);
        assert!(!result.is_allowed());
    }
}
