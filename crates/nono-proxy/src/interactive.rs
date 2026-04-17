//! Interactive network policy.
//!
//! When enabled, unknown hosts trigger a native OS dialog asking the user
//! whether to allow or deny access (once or permanently). Permanent decisions
//! are persisted to a learned-policy file next to the profile.
//!
//! ## Prompt backends
//!
//! - **macOS**: `osascript` displaying an AppleScript dialog.
//! - **Linux**: `zenity` (GNOME) or `kdialog` (KDE), whichever is available.
//! - **WSL**: `powershell.exe` invoking a WinForms `MessageBox`.
//!
//! If no backend is available (headless Linux without zenity/kdialog), the
//! default `on_unavailable` policy is applied (deny unless overridden).
//!
//! ## Security properties
//!
//! - Cloud metadata deny list and link-local IP blocks are NEVER promptable.
//!   Only hosts returning `FilterResult::DenyNotAllowed` trigger prompts.
//! - Concurrent requests for the same host coalesce behind a single prompt
//!   to avoid prompt spam.
//! - Permanent decisions are written to disk atomically (temp file + rename).
//! - Prompt timeouts default-deny so a missed prompt never silently allows.

use crate::error::{ProxyError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{oneshot, Mutex};
use tracing::{debug, info, warn};

/// Default timeout for waiting on a user dialog response.
const DEFAULT_PROMPT_TIMEOUT: Duration = Duration::from_secs(60);

/// Window title shared by every dialog backend so the notifier can find
/// and focus the dialog when the user clicks the notification.
const DIALOG_WINDOW_TITLE: &str = "nono: network access";

/// On-disk schema version for the learned policy file.
const LEARNED_POLICY_SCHEMA: u32 = 1;

/// A persistent decision about a host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermanentDecision {
    Allow,
    Deny,
}

/// Scope of a learned decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionScope {
    /// Exact hostname match (case-insensitive).
    Host,
    /// Wildcard suffix match (e.g., `example.com` matches `api.example.com`).
    Suffix,
}

/// A single learned policy entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearnedEntry {
    /// Pattern (lowercased). For `Suffix` scope, stored without leading dot.
    pub host: String,
    pub scope: DecisionScope,
    pub decision: PermanentDecision,
}

/// The on-disk learned-policy file format.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LearnedPolicyFile {
    #[serde(default = "default_schema")]
    schema: u32,
    #[serde(default)]
    entries: Vec<LearnedEntry>,
}

fn default_schema() -> u32 {
    LEARNED_POLICY_SCHEMA
}

impl Default for LearnedPolicyFile {
    fn default() -> Self {
        Self {
            schema: LEARNED_POLICY_SCHEMA,
            entries: Vec::new(),
        }
    }
}

/// The decision a user can make at a prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptDecision {
    AllowOnce,
    AllowPermanentHost,
    AllowPermanentSuffix,
    DenyOnce,
    DenyPermanentHost,
    DenyPermanentSuffix,
}

impl PromptDecision {
    #[must_use]
    pub fn is_allow(&self) -> bool {
        matches!(
            self,
            Self::AllowOnce | Self::AllowPermanentHost | Self::AllowPermanentSuffix
        )
    }

    #[must_use]
    pub fn is_permanent(&self) -> bool {
        !matches!(self, Self::AllowOnce | Self::DenyOnce)
    }

    #[must_use]
    pub fn scope(&self) -> Option<DecisionScope> {
        match self {
            Self::AllowPermanentHost | Self::DenyPermanentHost => Some(DecisionScope::Host),
            Self::AllowPermanentSuffix | Self::DenyPermanentSuffix => Some(DecisionScope::Suffix),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_permanent(&self) -> Option<PermanentDecision> {
        if self.is_permanent() {
            if self.is_allow() {
                Some(PermanentDecision::Allow)
            } else {
                Some(PermanentDecision::Deny)
            }
        } else {
            None
        }
    }
}

/// Configuration for the interactive policy subsystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InteractivePolicyConfig {
    /// Path where permanent decisions are persisted. If the parent directory
    /// does not exist, it is created at startup.
    pub learned_policy_path: PathBuf,

    /// Fallback policy when no dialog backend is available (headless Linux
    /// without zenity/kdialog, WSL without powershell.exe, etc.).
    #[serde(default)]
    pub on_unavailable: OnUnavailable,

    /// Timeout for a single prompt before the default-deny fallback kicks in.
    #[serde(default = "default_prompt_timeout_secs")]
    pub prompt_timeout_secs: u64,
}

fn default_prompt_timeout_secs() -> u64 {
    DEFAULT_PROMPT_TIMEOUT.as_secs()
}

impl InteractivePolicyConfig {
    #[must_use]
    pub fn prompt_timeout(&self) -> Duration {
        Duration::from_secs(self.prompt_timeout_secs)
    }
}

/// Behavior when no native dialog backend is available.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnUnavailable {
    /// Deny the request (safe default).
    #[default]
    Deny,
    /// Allow the request (useful for tests / CI).
    Allow,
}

/// Thread-safe interactive policy evaluator.
///
/// Loads the learned-policy file at construction, performs constant-time
/// host lookups, and coalesces concurrent prompts for the same host.
pub struct InteractivePolicy {
    config: InteractivePolicyConfig,
    /// Exact host -> permanent decision (lowercased keys).
    exact: Mutex<HashMap<String, PermanentDecision>>,
    /// Suffix patterns (lowercased, no leading dot) -> permanent decision.
    suffix: Mutex<Vec<(String, PermanentDecision)>>,
    /// In-flight prompts, keyed by lowercased hostname. Concurrent requests
    /// for the same host share a single prompt response.
    pending: Mutex<HashMap<String, Vec<oneshot::Sender<PromptDecision>>>>,
    /// Pluggable prompter (real or test double).
    prompter: Box<dyn Prompter>,
    /// Pluggable notifier. Fired once per triggered prompt — never for
    /// already-decided (stored) hosts.
    notifier: Box<dyn Notifier>,
}

impl std::fmt::Debug for InteractivePolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InteractivePolicy")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl InteractivePolicy {
    /// Load the policy from disk and build an evaluator.
    ///
    /// If the learned-policy file does not exist, starts with an empty policy.
    /// The file's parent directory is created if missing.
    pub fn load(config: InteractivePolicyConfig) -> Result<Arc<Self>> {
        Self::load_with_backends(config, default_prompter(), default_notifier())
    }

    /// Build an evaluator with a custom prompter (primarily for tests).
    ///
    /// Notifications default to no-op in this entry point so tests don't
    /// shell out to native utilities.
    pub fn load_with_prompter(
        config: InteractivePolicyConfig,
        prompter: Box<dyn Prompter>,
    ) -> Result<Arc<Self>> {
        Self::load_with_backends(config, prompter, Box::new(NoopNotifier))
    }

    /// Build an evaluator with custom prompter and notifier backends.
    pub fn load_with_backends(
        config: InteractivePolicyConfig,
        prompter: Box<dyn Prompter>,
        notifier: Box<dyn Notifier>,
    ) -> Result<Arc<Self>> {
        if let Some(parent) = config.learned_policy_path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    ProxyError::Config(format!(
                        "failed to create learned-policy dir {}: {}",
                        parent.display(),
                        e
                    ))
                })?;
            }
        }

        let file = load_file_if_exists(&config.learned_policy_path)?;
        let mut exact = HashMap::new();
        let mut suffix = Vec::new();
        for entry in file.entries {
            let normalized = entry.host.trim().to_lowercase();
            if normalized.is_empty() {
                continue;
            }
            match entry.scope {
                DecisionScope::Host => {
                    exact.insert(normalized, entry.decision);
                }
                DecisionScope::Suffix => {
                    let suffix_pattern = normalized.trim_start_matches('.').to_string();
                    if !suffix_pattern.is_empty() {
                        suffix.push((suffix_pattern, entry.decision));
                    }
                }
            }
        }

        Ok(Arc::new(Self {
            config,
            exact: Mutex::new(exact),
            suffix: Mutex::new(suffix),
            pending: Mutex::new(HashMap::new()),
            prompter,
            notifier,
        }))
    }

    /// Look up a stored decision for the given host, if any.
    ///
    /// Checks exact matches first, then longest suffix match.
    pub async fn stored_decision(&self, host: &str) -> Option<PermanentDecision> {
        let lower = host.to_lowercase();
        if let Some(dec) = self.exact.lock().await.get(&lower).copied() {
            return Some(dec);
        }
        let suffix = self.suffix.lock().await;
        let mut best: Option<(&str, PermanentDecision)> = None;
        for (pattern, decision) in suffix.iter() {
            if lower == *pattern || lower.ends_with(&format!(".{}", pattern)) {
                match best {
                    Some((prev, _)) if prev.len() >= pattern.len() => {}
                    _ => best = Some((pattern.as_str(), *decision)),
                }
            }
        }
        best.map(|(_, d)| d)
    }

    /// Decide whether `host` should be allowed. Triggers a prompt if no
    /// stored decision exists. Concurrent prompts for the same host coalesce.
    pub async fn decide(&self, host: &str, port: u16) -> Result<PromptDecision> {
        if let Some(stored) = self.stored_decision(host).await {
            return Ok(match stored {
                PermanentDecision::Allow => PromptDecision::AllowOnce,
                PermanentDecision::Deny => PromptDecision::DenyOnce,
            });
        }

        let key = host.to_lowercase();

        // Coalesce concurrent prompts for the same host.
        let (rx, is_leader) = {
            let mut pending = self.pending.lock().await;
            let (tx, rx) = oneshot::channel();
            let waiters = pending.entry(key.clone()).or_default();
            let is_leader = waiters.is_empty();
            waiters.push(tx);
            (rx, is_leader)
        };

        if is_leader {
            // Cancellation channel shared with the notifier so it can exit
            // promptly when the dialog is dismissed (important for
            // long-lived notifiers like notify-send --wait or the WSL
            // NotifyIcon event loop).
            let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);

            // Fire a native notification in parallel with the dialog so the
            // user sees the prompt even if the dialog is obscured. Only the
            // leader notifies — coalesced waiters stay silent.
            {
                let notifier = self.notifier.clone_box();
                let host_for_notify = host.to_string();
                tokio::task::spawn_blocking(move || {
                    notifier.notify(&host_for_notify, port, cancel_rx);
                });
            }

            // Run the prompt. Use spawn_blocking so the dialog subprocess
            // doesn't monopolise an async worker.
            let host_owned = host.to_string();
            let prompter = self.prompter.clone_box();
            let timeout = self.config.prompt_timeout();
            let fallback = match self.config.on_unavailable {
                OnUnavailable::Allow => PromptDecision::AllowOnce,
                OnUnavailable::Deny => PromptDecision::DenyOnce,
            };

            let decision = tokio::task::spawn_blocking(move || {
                prompter.prompt(&host_owned, port, timeout, fallback)
            })
            .await
            .unwrap_or(Ok(fallback))
            .unwrap_or(fallback);

            // Signal the notifier to tear down its subprocess.
            let _ = cancel_tx.send(true);

            if let Some(perm) = decision.as_permanent() {
                let scope = decision.scope().unwrap_or(DecisionScope::Host);
                // For suffix scope, persist the computed registered suffix
                // (e.g., `api.example.com` -> `example.com`) so future
                // subdomains are covered. For host scope, persist the exact
                // hostname.
                let pattern_to_store: String = match scope {
                    DecisionScope::Host => host.to_string(),
                    DecisionScope::Suffix => registered_suffix_hint(host),
                };
                self.record_permanent(&pattern_to_store, scope, perm)
                    .await?;
            }

            let waiters = {
                let mut pending = self.pending.lock().await;
                pending.remove(&key).unwrap_or_default()
            };
            for tx in waiters {
                let _ = tx.send(decision);
            }
            Ok(decision)
        } else {
            // Non-leader: wait for the leader's decision.
            rx.await.map_err(|_| {
                ProxyError::Config(
                    "interactive policy: prompt coordinator dropped before response".into(),
                )
            })
        }
    }

    /// Persist a permanent decision to memory + disk.
    async fn record_permanent(
        &self,
        host: &str,
        scope: DecisionScope,
        decision: PermanentDecision,
    ) -> Result<()> {
        let normalized = host.trim().to_lowercase();
        if normalized.is_empty() {
            return Ok(());
        }
        match scope {
            DecisionScope::Host => {
                self.exact.lock().await.insert(normalized.clone(), decision);
            }
            DecisionScope::Suffix => {
                let pattern = normalized.trim_start_matches('.').to_string();
                let mut suffix = self.suffix.lock().await;
                // Replace an existing entry for the same pattern.
                if let Some(existing) = suffix.iter_mut().find(|(p, _)| p == &pattern) {
                    existing.1 = decision;
                } else {
                    suffix.push((pattern, decision));
                }
            }
        }
        self.flush_to_disk().await
    }

    async fn flush_to_disk(&self) -> Result<()> {
        let exact = self.exact.lock().await;
        let suffix = self.suffix.lock().await;

        let mut entries: Vec<LearnedEntry> = exact
            .iter()
            .map(|(host, decision)| LearnedEntry {
                host: host.clone(),
                scope: DecisionScope::Host,
                decision: *decision,
            })
            .collect();
        for (pattern, decision) in suffix.iter() {
            entries.push(LearnedEntry {
                host: pattern.clone(),
                scope: DecisionScope::Suffix,
                decision: *decision,
            });
        }
        entries.sort_by(|a, b| a.host.cmp(&b.host));

        let file = LearnedPolicyFile {
            schema: LEARNED_POLICY_SCHEMA,
            entries,
        };
        let json = serde_json::to_string_pretty(&file).map_err(|e| {
            ProxyError::Config(format!("failed to serialize learned policy: {}", e))
        })?;

        // Atomic write: temp file + rename.
        let path = &self.config.learned_policy_path;
        let tmp_path = path.with_extension("json.tmp");
        std::fs::write(&tmp_path, json).map_err(|e| {
            ProxyError::Config(format!(
                "failed to write learned-policy temp file {}: {}",
                tmp_path.display(),
                e
            ))
        })?;
        std::fs::rename(&tmp_path, path).map_err(|e| {
            ProxyError::Config(format!(
                "failed to rename learned-policy temp file into place {}: {}",
                path.display(),
                e
            ))
        })?;
        info!(
            "Updated learned network policy: {} ({} entries)",
            path.display(),
            file.entries.len()
        );
        Ok(())
    }
}

fn load_file_if_exists(path: &Path) -> Result<LearnedPolicyFile> {
    if !path.exists() {
        return Ok(LearnedPolicyFile::default());
    }
    let data = std::fs::read_to_string(path).map_err(|e| {
        ProxyError::Config(format!(
            "failed to read learned-policy file {}: {}",
            path.display(),
            e
        ))
    })?;
    if data.trim().is_empty() {
        return Ok(LearnedPolicyFile::default());
    }
    let file: LearnedPolicyFile = serde_json::from_str(&data).map_err(|e| {
        ProxyError::Config(format!(
            "failed to parse learned-policy file {}: {}",
            path.display(),
            e
        ))
    })?;
    if file.schema != LEARNED_POLICY_SCHEMA {
        warn!(
            "Learned policy file {} has schema {}, expected {}: loading anyway",
            path.display(),
            file.schema,
            LEARNED_POLICY_SCHEMA
        );
    }
    debug!(
        "Loaded learned network policy from {}: {} entries",
        path.display(),
        file.entries.len()
    );
    Ok(file)
}

// ---------------------------------------------------------------------------
// Prompter trait + OS-specific implementations
// ---------------------------------------------------------------------------

/// Trait abstracting over dialog backends so tests can swap them out.
pub trait Prompter: Send + Sync {
    fn prompt(
        &self,
        host: &str,
        port: u16,
        timeout: Duration,
        on_unavailable: PromptDecision,
    ) -> Result<PromptDecision>;

    fn clone_box(&self) -> Box<dyn Prompter>;
}

/// Produce the best native prompter for the current environment.
pub fn default_prompter() -> Box<dyn Prompter> {
    Box::new(NativePrompter::new())
}

/// Dialog prompter that shells out to OS-native utilities.
#[derive(Debug, Clone)]
pub struct NativePrompter;

impl NativePrompter {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for NativePrompter {
    fn default() -> Self {
        Self::new()
    }
}

impl Prompter for NativePrompter {
    fn prompt(
        &self,
        host: &str,
        port: u16,
        timeout: Duration,
        on_unavailable: PromptDecision,
    ) -> Result<PromptDecision> {
        let backends = detect_backends();
        if backends.is_empty() {
            warn!(
                "No native dialog backend available; applying on_unavailable fallback for {}:{}",
                host, port
            );
            return Ok(on_unavailable);
        }
        for backend in backends {
            match backend.prompt(host, port, timeout) {
                Ok(decision) => return Ok(decision),
                Err(e) => {
                    warn!(
                        "Dialog backend {:?} failed for {}:{}: {}; trying next",
                        backend, host, port, e
                    );
                }
            }
        }
        Ok(on_unavailable)
    }

    fn clone_box(&self) -> Box<dyn Prompter> {
        Box::new(self.clone())
    }
}

// ---------------------------------------------------------------------------
// Notifier trait + native implementations
// ---------------------------------------------------------------------------

/// Trait abstracting over OS-native toast/banner notification backends.
///
/// Notifications run concurrently with the dialog prompt. The
/// `cancel_rx` parameter is signaled once the dialog is dismissed, so
/// backends that run interactive event loops (Linux `notify-send --wait`,
/// Windows NotifyIcon) can exit promptly and free their subprocess.
/// A failed notification never blocks or fails the policy decision.
pub trait Notifier: Send + Sync {
    /// Display a notification for an incoming prompt. The notifier may
    /// block for up to its own internal timeout while waiting for a
    /// click; `cancel_rx` being resolved must terminate the notifier
    /// within a reasonable time (< 1s).
    fn notify(&self, host: &str, port: u16, cancel_rx: tokio::sync::watch::Receiver<bool>);

    fn clone_box(&self) -> Box<dyn Notifier>;
}

/// Produce the best native notifier for the current environment.
#[must_use]
pub fn default_notifier() -> Box<dyn Notifier> {
    Box::new(NativeNotifier::new())
}

/// Notifier that shells out to OS-native notification utilities.
#[derive(Debug, Clone)]
pub struct NativeNotifier;

impl NativeNotifier {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for NativeNotifier {
    fn default() -> Self {
        Self::new()
    }
}

impl Notifier for NativeNotifier {
    fn notify(&self, host: &str, port: u16, cancel_rx: tokio::sync::watch::Receiver<bool>) {
        let backends = detect_notify_backends();
        if backends.is_empty() {
            debug!(
                "No native notification backend available; skipping notification for {}:{}",
                host, port
            );
            return;
        }
        for backend in &backends {
            match backend.notify(host, port, cancel_rx.clone()) {
                Ok(()) => return,
                Err(e) => {
                    debug!(
                        "Notification backend {:?} failed for {}:{}: {}; trying next",
                        backend, host, port, e
                    );
                }
            }
        }
    }

    fn clone_box(&self) -> Box<dyn Notifier> {
        Box::new(self.clone())
    }
}

/// Notifier that does nothing. Useful for tests and for disabling
/// notifications without taking the Prompter offline.
#[derive(Debug, Clone, Default)]
pub struct NoopNotifier;

impl Notifier for NoopNotifier {
    fn notify(&self, _host: &str, _port: u16, _cancel_rx: tokio::sync::watch::Receiver<bool>) {}

    fn clone_box(&self) -> Box<dyn Notifier> {
        Box::new(self.clone())
    }
}

#[derive(Debug, Clone, Copy)]
enum NotifyBackend {
    MacOsOsascript,
    LinuxNotifySend,
    WslPowershell,
}

fn detect_notify_backends() -> Vec<NotifyBackend> {
    let mut out = Vec::new();
    if cfg!(target_os = "macos") {
        if which("osascript") {
            out.push(NotifyBackend::MacOsOsascript);
        }
    } else if cfg!(target_os = "linux") {
        if which("notify-send") {
            out.push(NotifyBackend::LinuxNotifySend);
        }
        if is_wsl() && which("powershell.exe") {
            out.push(NotifyBackend::WslPowershell);
        }
    }
    out
}

impl NotifyBackend {
    fn notify(
        &self,
        host: &str,
        port: u16,
        cancel_rx: tokio::sync::watch::Receiver<bool>,
    ) -> Result<()> {
        match self {
            // macOS: osascript notifier is short-lived (a few seconds) and
            // doesn't run an interactive loop, so cancel is irrelevant.
            Self::MacOsOsascript => osascript_notify(host, port),
            Self::LinuxNotifySend => notify_send(host, port, cancel_rx),
            Self::WslPowershell => powershell_notify(host, port, cancel_rx),
        }
    }
}

const NOTIFY_TITLE: &str = "nono: network request";

fn notification_body(host: &str, port: u16) -> String {
    format!(
        "Sandboxed process wants to reach {}:{} \u{2014} a decision dialog is waiting.",
        host, port
    )
}

/// macOS notification.
///
/// Posts a banner via `osascript display notification` and returns. The
/// notifier does NOT wire up any click action: macOS attributes such
/// notifications to Script Editor.app, and there's no supported way to
/// suppress its launch on click without bundling nono into a proper
/// `.app`. Users are expected to treat the notification as passive.
///
/// Dialog focus is handled by the dialog backend itself: AppleScript
/// `choose from list` creates a modal window that the system places in
/// front when `osascript` becomes frontmost.
fn osascript_notify(host: &str, port: u16) -> Result<()> {
    let script = format!(
        "display notification \"{body}\" with title \"{ntitle}\" sound name \"Ping\"",
        body = escape_applescript(&notification_body(host, port)),
        ntitle = escape_applescript(NOTIFY_TITLE),
    );
    run_with_timeout("osascript", &["-e", &script], None, Duration::from_secs(5))?;
    Ok(())
}

/// Linux notification with a "Show" action that raises the dialog window.
///
/// Uses `notify-send --action=show=Show --wait` (available in libnotify
/// 0.8+). If the user clicks the action, notify-send writes the action
/// id ("show") to stdout; we then raise the dialog window with
/// `wmctrl -a <title>` or `xdotool search --name <title> windowactivate`.
///
/// Older notify-send versions don't support `--action` and will exit
/// with a usage error; in that case we fall back to a plain notification
/// (no click-to-focus, but the banner still appears).
fn notify_send(host: &str, port: u16, cancel_rx: tokio::sync::watch::Receiver<bool>) -> Result<()> {
    let body = notification_body(host, port);
    // Try the action-capable form first. `--wait` blocks until the
    // notification is dismissed OR an action is invoked. The cancel_rx
    // lets us kill notify-send as soon as the dialog closes.
    let rich_args = [
        "--app-name=nono",
        "--urgency=normal",
        "--action=show=Show",
        "--wait",
        NOTIFY_TITLE,
        &body,
    ];
    match run_with_timeout_cancellable(
        "notify-send",
        &rich_args,
        None,
        Duration::from_secs(120),
        Some(cancel_rx),
    ) {
        Ok((status, stdout)) if status == 0 => {
            let chosen = stdout.trim();
            if chosen == "show" {
                let _ = raise_linux_window(DIALOG_WINDOW_TITLE);
            }
            return Ok(());
        }
        Ok(_) | Err(_) => {
            // Fall through to plain notification (older libnotify).
        }
    }

    let fallback_args = ["--app-name=nono", "--urgency=normal", NOTIFY_TITLE, &body];
    run_with_timeout("notify-send", &fallback_args, None, Duration::from_secs(5))?;
    Ok(())
}

/// Raise a Linux X11 window by title. Tries `wmctrl` first, then `xdotool`.
/// Best-effort — silently succeeds if no WM tool is available.
fn raise_linux_window(title: &str) -> Result<()> {
    if which("wmctrl") {
        let _ = run_with_timeout("wmctrl", &["-a", title], None, Duration::from_secs(3));
        return Ok(());
    }
    if which("xdotool") {
        let _ = run_with_timeout(
            "xdotool",
            &["search", "--name", title, "windowactivate"],
            None,
            Duration::from_secs(3),
        );
        return Ok(());
    }
    Ok(())
}

/// WSL notification that activates the dialog window on click.
///
/// Uses a hidden WinForms `NotifyIcon` with a `BalloonTipClicked` event
/// handler. When the user clicks the balloon, the handler calls Win32
/// `FindWindow`/`SetForegroundWindow` to raise the dialog window by its
/// known title. The script runs its own message pump (`Application.Run`
/// with a short idle timer) so the click event is delivered, and
/// disposes the icon once the balloon closes or after a safety timeout.
fn powershell_notify(
    host: &str,
    port: u16,
    cancel_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let script = format!(
        r#"
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$sig = @'
[DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
public static extern System.IntPtr FindWindow(string lpClassName, string lpWindowName);
[DllImport("user32.dll")]
public static extern bool SetForegroundWindow(System.IntPtr hWnd);
[DllImport("user32.dll")]
public static extern bool ShowWindowAsync(System.IntPtr hWnd, int nCmdShow);
'@
if (-not ([System.Management.Automation.PSTypeName]'NonoWin32').Type) {{
    Add-Type -MemberDefinition $sig -Name 'NonoWin32' -Namespace 'Nono' -PassThru | Out-Null
}}
$n = New-Object System.Windows.Forms.NotifyIcon
$n.Icon = [System.Drawing.SystemIcons]::Information
$n.BalloonTipTitle = "{ntitle}"
$n.BalloonTipText = "{body}"
$n.Visible = $true
$script:shouldExit = $false
$onClick = {{
    try {{
        $h = [Nono.NonoWin32]::FindWindow($null, "{dtitle}")
        if ($h -ne [System.IntPtr]::Zero) {{
            [Nono.NonoWin32]::ShowWindowAsync($h, 9) | Out-Null  # SW_RESTORE
            [Nono.NonoWin32]::SetForegroundWindow($h) | Out-Null
        }}
    }} catch {{}}
    $script:shouldExit = $true
}}
$onClosed = {{ $script:shouldExit = $true }}
$n.add_BalloonTipClicked($onClick)
$n.add_BalloonTipClosed($onClosed)
$n.ShowBalloonTip(10000)
# Drain the Windows message queue for up to ~12s so click events are
# delivered. Exits early once the balloon is clicked/closed.
$end = (Get-Date).AddSeconds(12)
while ((Get-Date) -lt $end -and -not $script:shouldExit) {{
    [System.Windows.Forms.Application]::DoEvents()
    Start-Sleep -Milliseconds 100
}}
$n.Visible = $false
$n.Dispose()
"#,
        ntitle = powershell_escape(NOTIFY_TITLE),
        body = powershell_escape(&notification_body(host, port)),
        dtitle = powershell_escape(DIALOG_WINDOW_TITLE),
    );
    run_with_timeout_cancellable(
        "powershell.exe",
        &["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "-"],
        Some(&script),
        Duration::from_secs(15),
        Some(cancel_rx),
    )?;
    Ok(())
}

fn powershell_escape(s: &str) -> String {
    // PowerShell double-quoted strings: escape backtick, double-quote, and $.
    s.replace('`', "``")
        .replace('"', "`\"")
        .replace('$', "`$")
        .replace('\n', " ")
}

#[derive(Debug, Clone, Copy)]
enum DialogBackend {
    MacOsOsascript,
    LinuxZenity,
    LinuxKdialog,
    WslPowershell,
}

fn detect_backends() -> Vec<DialogBackend> {
    let mut out = Vec::new();
    if cfg!(target_os = "macos") {
        if which("osascript") {
            out.push(DialogBackend::MacOsOsascript);
        }
    } else if cfg!(target_os = "linux") {
        // WSL: prefer powershell.exe because there's usually no X/Wayland.
        if is_wsl() && which("powershell.exe") {
            out.push(DialogBackend::WslPowershell);
        }
        if which("zenity") {
            out.push(DialogBackend::LinuxZenity);
        }
        if which("kdialog") {
            out.push(DialogBackend::LinuxKdialog);
        }
        // Fall back to powershell.exe on WSL if zenity/kdialog missing.
        if out.is_empty() && is_wsl() && which("powershell.exe") {
            out.push(DialogBackend::WslPowershell);
        }
    }
    out
}

fn which(cmd: &str) -> bool {
    let path = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&path).any(|p| {
        let candidate = p.join(cmd);
        candidate.is_file() || (cfg!(windows) && candidate.with_extension("exe").is_file())
    })
}

fn is_wsl() -> bool {
    if !cfg!(target_os = "linux") {
        return false;
    }
    if std::env::var_os("WSL_DISTRO_NAME").is_some() || std::env::var_os("WSL_INTEROP").is_some() {
        return true;
    }
    // Fallback: look at /proc/version for Microsoft/WSL markers.
    std::fs::read_to_string("/proc/version")
        .map(|v| {
            let lower = v.to_lowercase();
            lower.contains("microsoft") || lower.contains("wsl")
        })
        .unwrap_or(false)
}

impl DialogBackend {
    fn prompt(&self, host: &str, port: u16, timeout: Duration) -> Result<PromptDecision> {
        match self {
            Self::MacOsOsascript => osascript_prompt(host, port, timeout),
            Self::LinuxZenity => zenity_prompt(host, port, timeout),
            Self::LinuxKdialog => kdialog_prompt(host, port, timeout),
            Self::WslPowershell => powershell_prompt(host, port, timeout),
        }
    }
}

/// Run a subprocess with a timeout and capture stdout.
fn run_with_timeout(
    program: &str,
    args: &[&str],
    stdin_data: Option<&str>,
    timeout: Duration,
) -> Result<(i32, String)> {
    run_with_timeout_cancellable(program, args, stdin_data, timeout, None)
}

/// Like `run_with_timeout`, but also listens for a cancellation signal
/// on the given watch channel. When `cancel_rx` resolves to `true`, the
/// subprocess is killed and the function returns `Ok((status, stdout))`.
fn run_with_timeout_cancellable(
    program: &str,
    args: &[&str],
    stdin_data: Option<&str>,
    timeout: Duration,
    mut cancel_rx: Option<tokio::sync::watch::Receiver<bool>>,
) -> Result<(i32, String)> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let mut cmd = Command::new(program);
    cmd.args(args);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    if stdin_data.is_some() {
        cmd.stdin(Stdio::piped());
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| ProxyError::Config(format!("failed to spawn {}: {}", program, e)))?;

    if let (Some(data), Some(mut stdin)) = (stdin_data, child.stdin.take()) {
        stdin.write_all(data.as_bytes()).map_err(|e| {
            ProxyError::Config(format!("failed to write stdin to {}: {}", program, e))
        })?;
    }

    // Poll wait with a deadline. process::Child has no async wait without
    // tokio's process feature, and we're already running inside spawn_blocking.
    let deadline = std::time::Instant::now() + timeout;
    loop {
        // Cooperative cancel: if the caller signalled that the dialog is
        // done, kill the subprocess and return its partial output.
        if let Some(rx) = cancel_rx.as_mut() {
            if *rx.borrow() {
                let _ = child.kill();
                let _ = child.wait();
                let mut stdout = String::new();
                if let Some(mut out) = child.stdout.take() {
                    use std::io::Read;
                    let _ = out.read_to_string(&mut stdout);
                }
                return Ok((0, stdout));
            }
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut stdout = String::new();
                if let Some(mut out) = child.stdout.take() {
                    use std::io::Read;
                    let _ = out.read_to_string(&mut stdout);
                }
                return Ok((status.code().unwrap_or(-1), stdout));
            }
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(ProxyError::Config(format!(
                        "{} dialog timed out after {:?}",
                        program, timeout
                    )));
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => {
                return Err(ProxyError::Config(format!(
                    "failed to wait for {}: {}",
                    program, e
                )));
            }
        }
    }
}

fn osascript_prompt(host: &str, port: u16, timeout: Duration) -> Result<PromptDecision> {
    // AppleScript "choose from list" with custom buttons.
    // We can't customise buttons in "display dialog" beyond 3, so we use
    // "choose from list" instead.
    let script = format!(
        r#"
set theChoices to {{"Allow once", "Allow permanently (this host)", "Allow permanently (*.{suffix})", "Deny once", "Deny permanently (this host)", "Deny permanently (*.{suffix})"}}
set theChoice to choose from list theChoices with title "{dialog_title}" with prompt "The sandboxed process is trying to reach:

    {host}:{port}

How should nono handle this destination?" default items {{"Deny once"}} OK button name "Select" cancel button name "Cancel"
if theChoice is false then
    return "deny_once"
else
    set c to item 1 of theChoice
    if c is "Allow once" then
        return "allow_once"
    else if c is "Allow permanently (this host)" then
        return "allow_permanent_host"
    else if c is "Allow permanently (*.{suffix})" then
        return "allow_permanent_suffix"
    else if c is "Deny once" then
        return "deny_once"
    else if c is "Deny permanently (this host)" then
        return "deny_permanent_host"
    else if c is "Deny permanently (*.{suffix})" then
        return "deny_permanent_suffix"
    else
        return "deny_once"
    end if
end if
"#,
        dialog_title = escape_applescript(DIALOG_WINDOW_TITLE),
        host = escape_applescript(host),
        port = port,
        suffix = escape_applescript(&registered_suffix_hint(host)),
    );

    let (_status, stdout) = run_with_timeout("osascript", &["-e", &script], None, timeout)?;
    let token = stdout.trim();
    parse_decision_token(token).ok_or_else(|| {
        ProxyError::Config(format!(
            "osascript returned unrecognised decision: {:?}",
            token
        ))
    })
}

fn zenity_prompt(host: &str, port: u16, timeout: Duration) -> Result<PromptDecision> {
    // zenity --list with radio buttons.
    let text = format!(
        "The sandboxed process is trying to reach:\n\n    {host}:{port}\n\nHow should nono handle this destination?",
        host = host,
        port = port
    );
    let suffix = registered_suffix_hint(host);
    let args = [
        "--list",
        "--radiolist",
        &format!("--title={}", DIALOG_WINDOW_TITLE),
        "--text",
        &text,
        "--column=Pick",
        "--column=Action",
        "--column=id",
        "--hide-column=3",
        "--print-column=3",
        "FALSE",
        "Allow once",
        "allow_once",
        "FALSE",
        "Allow permanently (this host)",
        "allow_permanent_host",
        "FALSE",
        &format!("Allow permanently (*.{})", suffix),
        "allow_permanent_suffix",
        "TRUE",
        "Deny once",
        "deny_once",
        "FALSE",
        "Deny permanently (this host)",
        "deny_permanent_host",
        "FALSE",
        &format!("Deny permanently (*.{})", suffix),
        "deny_permanent_suffix",
    ];
    let (status, stdout) = run_with_timeout("zenity", &args, None, timeout)?;
    if status != 0 {
        // User pressed Cancel.
        return Ok(PromptDecision::DenyOnce);
    }
    let token = stdout.trim();
    parse_decision_token(token).ok_or_else(|| {
        ProxyError::Config(format!(
            "zenity returned unrecognised decision: {:?}",
            token
        ))
    })
}

fn kdialog_prompt(host: &str, port: u16, timeout: Duration) -> Result<PromptDecision> {
    let text = format!(
        "The sandboxed process is trying to reach {host}:{port}.\nHow should nono handle this destination?",
        host = host,
        port = port
    );
    let suffix = registered_suffix_hint(host);
    let items = [
        "allow_once",
        "Allow once",
        "allow_permanent_host",
        "Allow permanently (this host)",
        "allow_permanent_suffix",
        &format!("Allow permanently (*.{})", suffix),
        "deny_once",
        "Deny once",
        "deny_permanent_host",
        "Deny permanently (this host)",
        "deny_permanent_suffix",
        &format!("Deny permanently (*.{})", suffix),
    ];
    let mut args = vec!["--title", DIALOG_WINDOW_TITLE, "--radiolist", &text];
    for i in (0..items.len()).step_by(2) {
        args.push(items[i]);
        args.push(items[i + 1]);
        args.push(if items[i] == "deny_once" { "on" } else { "off" });
    }
    let (status, stdout) = run_with_timeout("kdialog", &args, None, timeout)?;
    if status != 0 {
        return Ok(PromptDecision::DenyOnce);
    }
    let token = stdout.trim();
    parse_decision_token(token).ok_or_else(|| {
        ProxyError::Config(format!(
            "kdialog returned unrecognised decision: {:?}",
            token
        ))
    })
}

fn powershell_prompt(host: &str, port: u16, timeout: Duration) -> Result<PromptDecision> {
    let suffix = registered_suffix_hint(host);
    // Print the six choices, read a number from the user via a custom form.
    // Using System.Windows.Forms and a combo box for a native Windows dialog.
    let script = format!(
        r#"
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$form = New-Object System.Windows.Forms.Form
$form.Text = "{dialog_title}"
$form.Size = New-Object System.Drawing.Size(480,260)
$form.StartPosition = "CenterScreen"
$form.TopMost = $true

$label = New-Object System.Windows.Forms.Label
$label.Location = New-Object System.Drawing.Point(10,10)
$label.Size = New-Object System.Drawing.Size(460,60)
$label.Text = "The sandboxed process is trying to reach:`n`n    {host}:{port}`n`nHow should nono handle this destination?"
$form.Controls.Add($label)

$combo = New-Object System.Windows.Forms.ComboBox
$combo.Location = New-Object System.Drawing.Point(10,80)
$combo.Size = New-Object System.Drawing.Size(440,20)
$combo.DropDownStyle = "DropDownList"
$combo.Items.Add("Allow once")           | Out-Null
$combo.Items.Add("Allow permanently (this host)") | Out-Null
$combo.Items.Add("Allow permanently (*.{suffix})") | Out-Null
$combo.Items.Add("Deny once")            | Out-Null
$combo.Items.Add("Deny permanently (this host)") | Out-Null
$combo.Items.Add("Deny permanently (*.{suffix})") | Out-Null
$combo.SelectedIndex = 3
$form.Controls.Add($combo)

$ok = New-Object System.Windows.Forms.Button
$ok.Location = New-Object System.Drawing.Point(280,180)
$ok.Size = New-Object System.Drawing.Size(80,25)
$ok.Text = "OK"
$ok.DialogResult = [System.Windows.Forms.DialogResult]::OK
$form.AcceptButton = $ok
$form.Controls.Add($ok)

$cancel = New-Object System.Windows.Forms.Button
$cancel.Location = New-Object System.Drawing.Point(370,180)
$cancel.Size = New-Object System.Drawing.Size(80,25)
$cancel.Text = "Cancel"
$cancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
$form.CancelButton = $cancel
$form.Controls.Add($cancel)

$result = $form.ShowDialog()
if ($result -ne [System.Windows.Forms.DialogResult]::OK) {{
    Write-Output "deny_once"
    exit 0
}}
switch ($combo.SelectedIndex) {{
    0 {{ Write-Output "allow_once" }}
    1 {{ Write-Output "allow_permanent_host" }}
    2 {{ Write-Output "allow_permanent_suffix" }}
    3 {{ Write-Output "deny_once" }}
    4 {{ Write-Output "deny_permanent_host" }}
    5 {{ Write-Output "deny_permanent_suffix" }}
    default {{ Write-Output "deny_once" }}
}}
"#,
        dialog_title = DIALOG_WINDOW_TITLE,
        host = host,
        port = port,
        suffix = suffix
    );

    let (_status, stdout) = run_with_timeout(
        "powershell.exe",
        &["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "-"],
        Some(&script),
        timeout,
    )?;
    let token = stdout.lines().last().unwrap_or("").trim();
    parse_decision_token(token).ok_or_else(|| {
        ProxyError::Config(format!(
            "powershell.exe returned unrecognised decision: {:?}",
            token
        ))
    })
}

fn parse_decision_token(token: &str) -> Option<PromptDecision> {
    match token {
        "allow_once" => Some(PromptDecision::AllowOnce),
        "allow_permanent_host" => Some(PromptDecision::AllowPermanentHost),
        "allow_permanent_suffix" => Some(PromptDecision::AllowPermanentSuffix),
        "deny_once" => Some(PromptDecision::DenyOnce),
        "deny_permanent_host" => Some(PromptDecision::DenyPermanentHost),
        "deny_permanent_suffix" => Some(PromptDecision::DenyPermanentSuffix),
        _ => None,
    }
}

fn escape_applescript(s: &str) -> String {
    // AppleScript strings are escaped with backslash; also strip newlines.
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', " ")
}

/// Produce a suffix suggestion for "allow permanently by suffix". Strips the
/// leftmost label if the host looks like a subdomain (dotted, >=2 labels).
/// This is a UX heuristic, not a security boundary — the user can pick
/// "host only" if they prefer.
fn registered_suffix_hint(host: &str) -> String {
    let trimmed = host.trim().trim_start_matches('.').to_lowercase();
    if trimmed.is_empty() {
        return String::new();
    }
    // IP literals: suggest the host unchanged.
    if trimmed.parse::<std::net::IpAddr>().is_ok() {
        return trimmed;
    }
    // Strip brackets for IPv6.
    let trimmed = trimmed.trim_start_matches('[').trim_end_matches(']');
    let labels: Vec<&str> = trimmed.split('.').filter(|l| !l.is_empty()).collect();
    if labels.len() <= 2 {
        // "example.com" -> suggest "example.com".
        return labels.join(".");
    }
    labels[1..].join(".")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Test notifier that records how many times it was called.
    #[derive(Debug, Clone)]
    struct RecordingNotifier {
        calls: Arc<AtomicUsize>,
    }

    impl RecordingNotifier {
        fn new() -> (Self, Arc<AtomicUsize>) {
            let calls = Arc::new(AtomicUsize::new(0));
            (
                Self {
                    calls: calls.clone(),
                },
                calls,
            )
        }
    }

    impl Notifier for RecordingNotifier {
        fn notify(&self, _host: &str, _port: u16, _cancel_rx: tokio::sync::watch::Receiver<bool>) {
            self.calls.fetch_add(1, Ordering::SeqCst);
        }

        fn clone_box(&self) -> Box<dyn Notifier> {
            Box::new(self.clone())
        }
    }

    /// Test prompter that records how many times it was called.
    #[derive(Debug, Clone)]
    struct RecordingPrompter {
        decision: PromptDecision,
        calls: Arc<AtomicUsize>,
    }

    impl RecordingPrompter {
        fn new(decision: PromptDecision) -> (Self, Arc<AtomicUsize>) {
            let calls = Arc::new(AtomicUsize::new(0));
            (
                Self {
                    decision,
                    calls: calls.clone(),
                },
                calls,
            )
        }
    }

    impl Prompter for RecordingPrompter {
        fn prompt(
            &self,
            _host: &str,
            _port: u16,
            _timeout: Duration,
            _on_unavailable: PromptDecision,
        ) -> Result<PromptDecision> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.decision)
        }

        fn clone_box(&self) -> Box<dyn Prompter> {
            Box::new(self.clone())
        }
    }

    fn temp_policy_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("nono-interactive-{}", name));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("learned.json")
    }

    fn cfg(path: PathBuf) -> InteractivePolicyConfig {
        InteractivePolicyConfig {
            learned_policy_path: path,
            on_unavailable: OnUnavailable::Deny,
            prompt_timeout_secs: 1,
        }
    }

    #[tokio::test]
    async fn allow_once_does_not_persist() {
        let path = temp_policy_path("allow_once");
        let (prompter, calls) = RecordingPrompter::new(PromptDecision::AllowOnce);
        let policy =
            InteractivePolicy::load_with_prompter(cfg(path.clone()), Box::new(prompter)).unwrap();

        let d1 = policy.decide("example.com", 443).await.unwrap();
        assert_eq!(d1, PromptDecision::AllowOnce);
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // Second call should prompt again (nothing stored).
        let d2 = policy.decide("example.com", 443).await.unwrap();
        assert_eq!(d2, PromptDecision::AllowOnce);
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        assert!(
            !path.exists()
                || std::fs::read_to_string(&path)
                    .unwrap()
                    .contains("\"entries\": []")
        );
    }

    #[tokio::test]
    async fn allow_permanent_host_persists_and_is_reused() {
        let path = temp_policy_path("allow_perm_host");
        let (prompter, calls) = RecordingPrompter::new(PromptDecision::AllowPermanentHost);
        let policy =
            InteractivePolicy::load_with_prompter(cfg(path.clone()), Box::new(prompter)).unwrap();

        let d1 = policy.decide("api.example.com", 443).await.unwrap();
        assert_eq!(d1, PromptDecision::AllowPermanentHost);
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // Second call should hit the cached decision, no prompt.
        let d2 = policy.decide("api.example.com", 443).await.unwrap();
        assert!(d2.is_allow());
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // File must contain the entry.
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(raw.contains("api.example.com"));
        assert!(raw.contains("\"allow\""));
    }

    #[tokio::test]
    async fn allow_permanent_suffix_matches_subdomains() {
        let path = temp_policy_path("allow_perm_suffix");
        let (prompter, calls) = RecordingPrompter::new(PromptDecision::AllowPermanentSuffix);
        let policy =
            InteractivePolicy::load_with_prompter(cfg(path.clone()), Box::new(prompter)).unwrap();

        let _ = policy.decide("api.example.com", 443).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // suffix is derived from "api.example.com" -> "example.com".
        // A request for "static.example.com" must be covered without re-prompting.
        let d = policy.decide("static.example.com", 443).await.unwrap();
        assert!(d.is_allow());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn deny_permanent_is_enforced() {
        let path = temp_policy_path("deny_perm");
        let (prompter, calls) = RecordingPrompter::new(PromptDecision::DenyPermanentHost);
        let policy =
            InteractivePolicy::load_with_prompter(cfg(path.clone()), Box::new(prompter)).unwrap();

        let d1 = policy.decide("evil.example.com", 443).await.unwrap();
        assert!(!d1.is_allow());
        let d2 = policy.decide("evil.example.com", 443).await.unwrap();
        assert!(!d2.is_allow());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn decisions_survive_reload() {
        let path = temp_policy_path("reload");
        let (prompter, _) = RecordingPrompter::new(PromptDecision::AllowPermanentHost);
        {
            let policy =
                InteractivePolicy::load_with_prompter(cfg(path.clone()), Box::new(prompter))
                    .unwrap();
            let _ = policy.decide("cache.example.com", 443).await.unwrap();
        }

        // Reload from disk with a prompter that would fail if called.
        let (prompter2, calls2) = RecordingPrompter::new(PromptDecision::DenyPermanentHost);
        let policy2 =
            InteractivePolicy::load_with_prompter(cfg(path.clone()), Box::new(prompter2)).unwrap();
        let stored = policy2.stored_decision("cache.example.com").await;
        assert_eq!(stored, Some(PermanentDecision::Allow));
        let d = policy2.decide("cache.example.com", 443).await.unwrap();
        assert!(d.is_allow());
        assert_eq!(calls2.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn suffix_hint_strips_leftmost_label() {
        assert_eq!(registered_suffix_hint("api.example.com"), "example.com");
        assert_eq!(
            registered_suffix_hint("www.deeply.nested.com"),
            "deeply.nested.com"
        );
        assert_eq!(registered_suffix_hint("example.com"), "example.com");
        assert_eq!(registered_suffix_hint("localhost"), "localhost");
    }

    #[test]
    fn suffix_hint_preserves_ip_literal() {
        assert_eq!(registered_suffix_hint("10.0.0.1"), "10.0.0.1");
    }

    #[test]
    fn parse_decision_tokens() {
        assert_eq!(
            parse_decision_token("allow_once"),
            Some(PromptDecision::AllowOnce)
        );
        assert_eq!(
            parse_decision_token("deny_permanent_suffix"),
            Some(PromptDecision::DenyPermanentSuffix)
        );
        assert_eq!(parse_decision_token("nonsense"), None);
    }

    #[tokio::test]
    async fn notifier_fires_once_per_prompt_and_not_for_stored_decision() {
        let path = temp_policy_path("notify");
        let (prompter, _prompt_calls) = RecordingPrompter::new(PromptDecision::AllowPermanentHost);
        let (notifier, notify_calls) = RecordingNotifier::new();
        let policy = InteractivePolicy::load_with_backends(
            cfg(path.clone()),
            Box::new(prompter),
            Box::new(notifier),
        )
        .unwrap();

        // First call: no stored decision → prompt → one notification.
        let _ = policy.decide("banner.example.com", 443).await.unwrap();
        // Notifier is spawned on a blocking thread; give it a moment.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(notify_calls.load(Ordering::SeqCst), 1);

        // Second call: permanent allow cached → no prompt, no notification.
        let _ = policy.decide("banner.example.com", 443).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(notify_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn notifier_coalesced_waiters_do_not_double_notify() {
        let path = temp_policy_path("notify_coalesce");
        // Use a prompter that blocks briefly to exercise the coalescing path.
        #[derive(Debug, Clone)]
        struct SlowPrompter;
        impl Prompter for SlowPrompter {
            fn prompt(
                &self,
                _host: &str,
                _port: u16,
                _timeout: Duration,
                _on_unavailable: PromptDecision,
            ) -> Result<PromptDecision> {
                std::thread::sleep(Duration::from_millis(150));
                Ok(PromptDecision::AllowOnce)
            }
            fn clone_box(&self) -> Box<dyn Prompter> {
                Box::new(self.clone())
            }
        }

        let (notifier, notify_calls) = RecordingNotifier::new();
        let policy = InteractivePolicy::load_with_backends(
            cfg(path.clone()),
            Box::new(SlowPrompter),
            Box::new(notifier),
        )
        .unwrap();

        let p1 = Arc::clone(&policy);
        let p2 = Arc::clone(&policy);
        let t1 = tokio::spawn(async move { p1.decide("coalesce.example.com", 443).await });
        let t2 = tokio::spawn(async move { p2.decide("coalesce.example.com", 443).await });
        let _ = t1.await.unwrap().unwrap();
        let _ = t2.await.unwrap().unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        // Only the leader should have notified.
        assert_eq!(notify_calls.load(Ordering::SeqCst), 1);
    }
}
