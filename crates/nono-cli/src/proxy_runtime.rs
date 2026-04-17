use crate::cli::SandboxArgs;
use crate::launch_runtime::ProxyLaunchOptions;
use crate::network_policy;
use crate::sandbox_prepare::{validate_external_proxy_bypass, PreparedSandbox};
use nono::{CapabilitySet, NonoError, Result};
use std::path::PathBuf;
use tracing::info;
use tracing::warn;

pub(crate) struct ActiveProxyRuntime {
    pub(crate) env_vars: Vec<(String, String)>,
    pub(crate) handle: Option<nono_proxy::server::ProxyHandle>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct EffectiveProxySettings {
    pub(crate) network_profile: Option<String>,
    pub(crate) allow_domain: Vec<String>,
    pub(crate) credentials: Vec<String>,
}

pub(crate) fn prepare_proxy_launch_options(
    args: &SandboxArgs,
    prepared: &PreparedSandbox,
    silent: bool,
) -> Result<ProxyLaunchOptions> {
    validate_external_proxy_bypass(args, prepared)?;

    let effective_proxy = resolve_effective_proxy_settings(args, prepared);
    let network_profile = effective_proxy.network_profile;
    let allow_domain = effective_proxy.allow_domain;
    let credentials = effective_proxy.credentials;
    let allow_bind_ports = merge_dedup_ports(&prepared.listen_ports, &args.allow_bind);

    let upstream_proxy = if args.allow_net {
        None
    } else {
        args.external_proxy
            .clone()
            .or_else(|| prepared.upstream_proxy.clone())
    };

    let upstream_bypass = if args.allow_net {
        Vec::new()
    } else if args.external_proxy.is_some() {
        args.external_proxy_bypass.clone()
    } else {
        let mut bypass = prepared.upstream_bypass.clone();
        bypass.extend(args.external_proxy_bypass.clone());
        bypass
    };

    // Resolve interactive-network-prompt settings. The CLI flag, or a
    // profile-level `network_prompt` object with `enabled=true`, enables
    // the interactive policy. The CLI flag always wins.
    let profile_prompt = prepared
        .network_prompt
        .as_ref()
        .filter(|cfg| cfg.enabled)
        .cloned();
    let interactive_enabled = args.network_prompt || profile_prompt.is_some();
    let interactive_learned_path = if interactive_enabled {
        Some(resolve_learned_policy_path(
            args,
            prepared,
            profile_prompt.as_ref(),
        )?)
    } else {
        None
    };
    let interactive_timeout_secs = profile_prompt.as_ref().and_then(|c| c.prompt_timeout_secs);
    let interactive_on_unavailable = profile_prompt
        .as_ref()
        .and_then(|c| c.on_unavailable.clone());

    let active = if matches!(prepared.caps.network_mode(), nono::NetworkMode::Blocked) {
        if !credentials.is_empty()
            || network_profile.is_some()
            || !allow_domain.is_empty()
            || upstream_proxy.is_some()
            || interactive_enabled
        {
            warn!(
                "--block-net is active; ignoring proxy configuration \
                 that would re-enable network access"
            );
            if !silent {
                eprintln!(
                    "  [nono] Warning: --block-net overrides proxy/credential settings. \
                     Network remains fully blocked."
                );
            }
        }
        false
    } else {
        matches!(
            prepared.caps.network_mode(),
            nono::NetworkMode::ProxyOnly { .. }
        ) || !credentials.is_empty()
            || network_profile.is_some()
            || !allow_domain.is_empty()
            || upstream_proxy.is_some()
            || interactive_enabled
    };

    Ok(ProxyLaunchOptions {
        active,
        network_profile,
        allow_domain,
        credentials,
        custom_credentials: prepared.custom_credentials.clone(),
        upstream_proxy,
        upstream_bypass,
        allow_bind_ports,
        proxy_port: args.proxy_port,
        open_url_origins: prepared.open_url_origins.clone(),
        open_url_allow_localhost: prepared.open_url_allow_localhost,
        allow_launch_services_active: prepared.allow_launch_services_active,
        interactive_enabled,
        interactive_learned_path,
        interactive_timeout_secs,
        interactive_on_unavailable,
    })
}

/// Resolve the path where permanent interactive decisions should be stored.
///
/// Precedence:
/// 1. Profile override `network_prompt.learned_policy_path`.
/// 2. Sibling of the profile file: `<profile-path>.learned.json`.
/// 3. Under the user config dir: `~/.config/nono/learned/<profile-name>.json`.
/// 4. Final fallback: `~/.config/nono/learned/ad-hoc.json`.
fn resolve_learned_policy_path(
    args: &SandboxArgs,
    prepared: &PreparedSandbox,
    profile_prompt: Option<&crate::profile::NetworkPromptConfig>,
) -> Result<PathBuf> {
    if let Some(explicit) = profile_prompt.and_then(|p| p.learned_policy_path.clone()) {
        return Ok(explicit);
    }
    if let Some(profile_path) = &prepared.profile_path {
        let mut out = profile_path.clone();
        // <name>.json -> <name>.learned.json
        if let Some(stem) = profile_path.file_stem().and_then(|s| s.to_str()) {
            let new_name = format!("{}.learned.json", stem);
            if let Some(parent) = profile_path.parent() {
                out = parent.join(new_name);
            }
        } else {
            out.set_extension("learned.json");
        }
        return Ok(out);
    }
    // Built-in profile or no profile: fall back to per-name file in the user
    // config dir, or a generic ad-hoc file when no profile name is set.
    let base = user_config_dir()?.join("nono").join("learned");
    let name = args
        .profile
        .as_deref()
        .map(sanitize_profile_name)
        .unwrap_or_else(|| "ad-hoc".to_string());
    Ok(base.join(format!("{}.json", name)))
}

fn user_config_dir() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os("XDG_CONFIG_HOME") {
        let p = PathBuf::from(dir);
        if !p.as_os_str().is_empty() {
            return Ok(p);
        }
    }
    if let Some(home) = std::env::var_os("HOME") {
        return Ok(PathBuf::from(home).join(".config"));
    }
    Err(NonoError::SandboxInit(
        "cannot resolve user config dir: $HOME and $XDG_CONFIG_HOME are unset".into(),
    ))
}

fn sanitize_profile_name(name: &str) -> String {
    // Strip path components and keep it filesystem-safe.
    let last = std::path::Path::new(name)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(name);
    last.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

pub(crate) fn resolve_effective_proxy_settings(
    args: &SandboxArgs,
    prepared: &PreparedSandbox,
) -> EffectiveProxySettings {
    if args.allow_net {
        return EffectiveProxySettings {
            network_profile: None,
            allow_domain: Vec::new(),
            credentials: Vec::new(),
        };
    }

    let network_profile = args
        .network_profile
        .clone()
        .or_else(|| prepared.network_profile.clone());
    let mut allow_domain = prepared.allow_domain.clone();
    allow_domain.extend(args.allow_proxy.clone());
    let mut credentials = prepared.credentials.clone();
    credentials.extend(args.proxy_credential.clone());

    EffectiveProxySettings {
        network_profile,
        allow_domain,
        credentials,
    }
}

pub(crate) fn merge_dedup_ports(a: &[u16], b: &[u16]) -> Vec<u16> {
    let mut ports = a.to_vec();
    ports.extend_from_slice(b);
    ports.sort_unstable();
    ports.dedup();
    ports
}

pub(crate) fn build_proxy_config_from_flags(
    proxy: &ProxyLaunchOptions,
) -> Result<nono_proxy::config::ProxyConfig> {
    let net_policy_json = crate::config::embedded::embedded_network_policy_json();
    let net_policy = network_policy::load_network_policy(net_policy_json)?;

    let mut resolved = if let Some(ref profile_name) = proxy.network_profile {
        network_policy::resolve_network_profile(&net_policy, profile_name)?
    } else {
        network_policy::ResolvedNetworkPolicy {
            hosts: Vec::new(),
            suffixes: Vec::new(),
            routes: Vec::new(),
            profile_credentials: Vec::new(),
        }
    };

    let mut all_credentials = resolved.profile_credentials.clone();
    for cred in &proxy.credentials {
        if !all_credentials.contains(cred) {
            all_credentials.push(cred.clone());
        }
    }

    let routes = network_policy::resolve_credentials(
        &net_policy,
        &all_credentials,
        &proxy.custom_credentials,
    )?;
    resolved.routes = routes;

    let expanded_allow_domain =
        network_policy::expand_proxy_allow(&net_policy, &proxy.allow_domain);
    let mut proxy_config = network_policy::build_proxy_config(&resolved, &expanded_allow_domain);

    if let Some(ref addr) = proxy.upstream_proxy {
        proxy_config.external_proxy = Some(nono_proxy::config::ExternalProxyConfig {
            address: addr.clone(),
            auth: None,
            bypass_hosts: proxy.upstream_bypass.clone(),
        });
    }

    if let Some(port) = proxy.proxy_port {
        proxy_config.bind_port = port;
    }

    if proxy.interactive_enabled {
        let learned_path = proxy.interactive_learned_path.clone().ok_or_else(|| {
            NonoError::SandboxInit(
                "interactive network prompt enabled but no learned-policy path resolved".into(),
            )
        })?;
        let on_unavailable = match proxy
            .interactive_on_unavailable
            .as_deref()
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            Some("allow") => nono_proxy::interactive::OnUnavailable::Allow,
            Some("deny") | None => nono_proxy::interactive::OnUnavailable::Deny,
            Some(other) => {
                return Err(NonoError::SandboxInit(format!(
                    "invalid network_prompt.on_unavailable value {:?}; expected 'allow' or 'deny'",
                    other
                )));
            }
        };
        proxy_config.interactive = Some(nono_proxy::interactive::InteractivePolicyConfig {
            learned_policy_path: learned_path,
            on_unavailable,
            prompt_timeout_secs: proxy.interactive_timeout_secs.unwrap_or(60),
        });
    }

    Ok(proxy_config)
}

pub(crate) fn start_proxy_runtime(
    proxy: &ProxyLaunchOptions,
    caps: &mut CapabilitySet,
) -> Result<ActiveProxyRuntime> {
    if !proxy.active {
        return Ok(ActiveProxyRuntime {
            env_vars: Vec::new(),
            handle: None,
        });
    }

    let mut proxy_config = build_proxy_config_from_flags(proxy)?;
    proxy_config.direct_connect_ports = caps.tcp_connect_ports().to_vec();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|e| NonoError::SandboxInit(format!("Failed to start proxy runtime: {}", e)))?;
    let handle = rt
        .block_on(async { nono_proxy::server::start(proxy_config.clone()).await })
        .map_err(|e| NonoError::SandboxInit(format!("Failed to start proxy: {}", e)))?;

    let port = handle.port;
    if proxy.allow_bind_ports.is_empty() {
        info!("Network proxy started on localhost:{}", port);
    } else {
        info!(
            "Network proxy started on localhost:{}, bind ports: {:?}",
            port, proxy.allow_bind_ports
        );
    }
    caps.set_network_mode_mut(nono::NetworkMode::ProxyOnly {
        port,
        bind_ports: proxy.allow_bind_ports.clone(),
    });

    let mut env_vars: Vec<(String, String)> = Vec::new();
    for (key, value) in handle.env_vars() {
        env_vars.push((key, value));
    }

    for (key, value) in handle.credential_env_vars(&proxy_config) {
        env_vars.push((key, value));
    }

    std::mem::forget(rt);

    Ok(ActiveProxyRuntime {
        env_vars,
        handle: Some(handle),
    })
}
