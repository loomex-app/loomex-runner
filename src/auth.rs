use crate::{
    api::{Api, SignedCredential, key_proof, now},
    state as runner_state,
};
use anyhow::{Result, anyhow, bail, ensure};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use ed25519_dalek::SigningKey;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, future::Future, sync::Arc, time::Duration};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::sync::Mutex;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
};

const SERVICE: &str = "app.loomex.runner.v1";
const ACCOUNT: &str = "installation";
pub(crate) const STORE_IO_BUDGET: Duration = Duration::from_secs(2);
// Admission to the single auth operation owner is independent of network work.
// Store access retains its separate two-second IO budget.
pub(crate) const AUTH_LOCK_BUDGET: Duration = Duration::from_secs(2);
// Retains the qualified startup observation allowance independently of ordinary
// operation admission. Health may wait for an existing owner, never recover it.
const AUTH_STARTUP_OBSERVATION_BUDGET: Duration = Duration::from_secs(15);

fn credential_store_code(error: &anyhow::Error) -> &'static str {
    match error.to_string().as_str() {
        "STORE_ACCESS_REQUIRED" => "STORE_ACCESS_REQUIRED",
        "STORE_ACCESS_DENIED" => "STORE_ACCESS_DENIED",
        "STORE_OPERATION_PENDING" => "STORE_OPERATION_PENDING",
        "STORE_INVALID" => "STORE_INVALID",
        _ => "STORE_UNAVAILABLE",
    }
}

#[cfg(target_os = "macos")]
fn noninteractive_password_options(
    service: &str,
    account: &str,
) -> security_framework::passwords::PasswordOptions {
    use core_foundation::{base::TCFType, string::CFString};
    use security_framework_sys::item::kSecUseAuthenticationUI;
    // The existing sys crate omits this documented Security constant. No new
    // framework, authentication context, global policy or item ACL is created.
    unsafe extern "C" {
        static kSecUseAuthenticationUIFail: core_foundation::string::CFStringRef;
    }
    let mut options =
        security_framework::passwords::PasswordOptions::new_generic_password(service, account);
    #[allow(deprecated)]
    options.query.push(unsafe {
        (
            CFString::wrap_under_get_rule(kSecUseAuthenticationUI),
            CFString::wrap_under_get_rule(kSecUseAuthenticationUIFail).into_CFType(),
        )
    });
    options
}

// This path is called only by the explicit foreground daemon-binary probe.
// Omitting kSecUseAuthenticationUI uses Apple's documented Allow default;
// ordinary daemon operations continue to pass Fail above.
#[cfg(target_os = "macos")]
fn foreground_password_options(
    service: &str,
    account: &str,
) -> security_framework::passwords::PasswordOptions {
    security_framework::passwords::PasswordOptions::new_generic_password(service, account)
}

#[cfg(target_os = "macos")]
fn probe_password(options: security_framework::passwords::PasswordOptions) -> &'static str {
    match security_framework::passwords::generic_password(options) {
        Ok(mut bytes) => {
            bytes.fill(0);
            "AUTHORIZED"
        }
        Err(error) if error.code() == -25300 => "ABSENT",
        Err(error) if matches!(error.code(), -25308 | -25315) => "ACCESS_REQUIRED",
        Err(error) if error.code() == -25293 => "ACCESS_DENIED",
        Err(_) => "UNAVAILABLE",
    }
}

/// Fixed-status read of the exact existing item by the daemon executable.
/// The foreground form may display macOS authorization UI, and is never used
/// by normal daemon startup or local-control requests.
#[cfg(target_os = "macos")]
pub fn credential_store_probe(foreground_authorization: bool) -> &'static str {
    if foreground_authorization {
        probe_password(foreground_password_options(SERVICE, ACCOUNT))
    } else {
        probe_password(noninteractive_password_options(SERVICE, ACCOUNT))
    }
}

#[cfg(target_os = "macos")]
fn native_store_error(status: i32) -> anyhow::Error {
    // InteractionNotAllowed/InteractionRequired do not identify an ACL or a
    // globally locked keychain. Preserve that uncertainty in the public code.
    anyhow!(match status {
        -25308 | -25315 => "STORE_ACCESS_REQUIRED",
        -25293 => "STORE_ACCESS_DENIED",
        _ => "STORE_UNAVAILABLE",
    })
}
const BROWSER_AUTH_CSS: &str = include_str!("../assets/browser_authority.css");

#[cfg(target_os = "macos")]
async fn launch_browser(url: &str) -> Result<()> {
    use std::process::Stdio;
    let status = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::process::Command::new("/usr/bin/open")
            .arg(url)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .status(),
    )
    .await
    .map_err(|_| anyhow!("BROWSER_LAUNCH_TIMEOUT"))?
    .map_err(|_| anyhow!("BROWSER_LAUNCH_FAILED"))?;
    ensure!(status.success(), "BROWSER_LAUNCH_FAILED");
    Ok(())
}

#[cfg(not(target_os = "macos"))]
async fn launch_browser(_url: &str) -> Result<()> {
    bail!("BROWSER_LAUNCH_UNAVAILABLE")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BrowserCallbackOutcome {
    SignedIn,
    Declined,
    RecoveryRequired,
    Invalid,
}

fn browser_callback_response(outcome: BrowserCallbackOutcome) -> String {
    let (status, reason, title, description, message_class) = match outcome {
        BrowserCallbackOutcome::SignedIn => (
            200,
            "OK",
            "Signed in",
            "Return to the Loomex connection card to finish setup.",
            "auth-message--success",
        ),
        BrowserCallbackOutcome::Declined => (
            200,
            "OK",
            "Sign-in declined",
            "You can return to Loomex.",
            "",
        ),
        BrowserCallbackOutcome::RecoveryRequired => (
            202,
            "Accepted",
            "Sign-in needs attention",
            "Return to Loomex to finish signing in.",
            "",
        ),
        BrowserCallbackOutcome::Invalid => (
            400,
            "Bad Request",
            "Sign-in unavailable",
            "Return to Loomex and start again.",
            "auth-message--error",
        ),
    };
    let style_hash = STANDARD.encode(Sha256::digest(BROWSER_AUTH_CSS.as_bytes()));
    let body = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><meta name=\"referrer\" content=\"no-referrer\"><title>{title} · Loomex</title><style>{BROWSER_AUTH_CSS}</style></head><body class=\"auth-page\"><div class=\"auth-shell\"><div class=\"auth-brand\"><span class=\"auth-brand-mark\" aria-hidden=\"true\">L</span>Loomex</div><main class=\"auth-card\"><h1 class=\"auth-title\">{title}</h1><p class=\"auth-message {message_class}\" role=\"status\">{description}</p></main></div></body></html>"
    );
    format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/html; charset=utf-8\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: default-src 'none'; style-src 'sha256-{style_hash}'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}
trait Store: Send + Sync {
    #[cfg(test)]
    fn synthetic_fixture(&self) -> bool {
        false
    }
    fn load(&self) -> Result<Option<Vec<u8>>>;
    fn save(&self, data: &[u8]) -> Result<()>;
    fn delete(&self) -> Result<()> {
        bail!("STORE_UNAVAILABLE")
    }
}
struct NativeStore;

#[cfg(test)]
#[derive(Default)]
struct MemoryStore(std::sync::Mutex<Option<Vec<u8>>>);
#[cfg(test)]
impl Store for MemoryStore {
    fn synthetic_fixture(&self) -> bool {
        true
    }
    fn load(&self) -> Result<Option<Vec<u8>>> {
        Ok(self.0.lock().unwrap().clone())
    }
    fn save(&self, bytes: &[u8]) -> Result<()> {
        *self.0.lock().unwrap() = Some(bytes.to_vec());
        Ok(())
    }
    fn delete(&self) -> Result<()> {
        *self.0.lock().unwrap() = None;
        Ok(())
    }
}
#[cfg(target_os = "macos")]
impl Store for NativeStore {
    fn load(&self) -> Result<Option<Vec<u8>>> {
        match security_framework::passwords::generic_password(noninteractive_password_options(
            SERVICE, ACCOUNT,
        )) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.code() == -25300 => Ok(None),
            Err(error) => Err(native_store_error(error.code())),
        }
    }
    fn save(&self, data: &[u8]) -> Result<()> {
        security_framework::passwords::set_generic_password_options(
            data,
            noninteractive_password_options(SERVICE, ACCOUNT),
        )
        .map_err(|error| native_store_error(error.code()))
    }
    fn delete(&self) -> Result<()> {
        match security_framework::passwords::delete_generic_password_options(
            noninteractive_password_options(SERVICE, ACCOUNT),
        ) {
            Ok(()) => Ok(()),
            Err(error) if error.code() == -25300 => Ok(()),
            Err(error) => Err(native_store_error(error.code())),
        }
    }
}
#[cfg(not(target_os = "macos"))]
impl Store for NativeStore {
    fn load(&self) -> Result<Option<Vec<u8>>> {
        bail!("STORE_UNAVAILABLE")
    }
    fn save(&self, _: &[u8]) -> Result<()> {
        bail!("STORE_UNAVAILABLE")
    }
}
#[derive(Clone, Serialize, Deserialize)]
struct Token {
    access: String,
    refresh: String,
    subject: String,
    expires_at: u64,
}
impl Token {
    fn usable(&self) -> bool {
        self.usable_at(now())
    }
    fn usable_at(&self, timestamp: u64) -> bool {
        self.expires_at > timestamp.saturating_add(60)
    }
    fn signed(&self, state: &ProtectedState) -> SignedCredential {
        SignedCredential {
            token: self.access.clone(),
            subject: self.subject.clone(),
            private_key: state.private_key,
        }
    }
}
#[derive(Clone, Default, Serialize, Deserialize)]
struct Login {
    key: String,
    runner_name: String,
    #[serde(default)]
    flow_id: String,
    expires_at: u64,
    #[serde(default)]
    authorization_url: Option<String>,
    #[serde(default)]
    transaction_id: Option<String>,
    #[serde(default)]
    redirect_uri: Option<String>,
    #[serde(default)]
    browser_state: Option<String>,
    #[serde(default)]
    code_verifier: Option<String>,
    #[serde(default)]
    received_code: Option<String>,
}
#[derive(Clone, Serialize, Deserialize)]
struct OrganizationProfile {
    name: Option<String>,
    slug: Option<String>,
    enrolled: bool,
}
#[derive(Clone, Serialize, Deserialize)]
enum Target {
    Bootstrap,
    BrowserExchange,
    BrowserCancel,
    DeviceRefresh,
    ChildRefresh(String),
    Enroll(String),
}
#[derive(Clone, Serialize, Deserialize)]
struct Pending {
    target: Target,
    route: String,
    body: Value,
    // Persisted before dispatch. A retry must retain this original bound so a
    // recovered response cannot acquire a new lifetime at receipt time.
    started_at: u64,
    // Retained only to decode pre-0.3.35 Keychain records. Exact proof-bound
    // recovery is repeatable on compatible backends until the server deadline.
    #[serde(default)]
    recovery_used: bool,
    // Kept until proof-bound cancellation confirms that the older operation
    // cannot issue credentials. Never sent to the backend. Old stores omit it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    superseded: Option<Box<Pending>>,
}
impl Pending {
    fn can_recover(&self) -> bool {
        // started_at records when persistence was queued, not when the request
        // reached the server. A blocked Keychain write or process restart makes
        // that timestamp unsuitable for enforcing the server's 30-second window.
        // The backend validates expiry and exact proof/credential-family identity.
        true
    }
}
#[derive(Serialize, Deserialize)]
struct ProtectedState {
    installation_id: String,
    private_key: [u8; 32],
    device: Option<Token>,
    children: BTreeMap<String, Token>,
    #[serde(default)]
    organization_profiles: BTreeMap<String, OrganizationProfile>,
    active_organization: Option<String>,
    login: Option<Login>,
    pending: Option<Pending>,
    logout_pending: bool,
    #[serde(default)]
    persona_state: BTreeMap<String, Value>,
}
impl ProtectedState {
    fn fresh() -> Self {
        Self {
            installation_id: uuid::Uuid::new_v4().to_string(),
            private_key: SigningKey::generate(&mut rand::rngs::OsRng).to_bytes(),
            device: None,
            children: BTreeMap::new(),
            organization_profiles: BTreeMap::new(),
            active_organization: None,
            login: None,
            pending: None,
            logout_pending: false,
            persona_state: BTreeMap::new(),
        }
    }
}
#[derive(Clone)]
pub struct Auth {
    api: Api,
    store: Arc<dyn Store>,
    // Serializes complete auth operations, including exact-proof recovery.
    operation_lock: Arc<Mutex<()>>,
    store_lock: Arc<Mutex<()>>,
    store_owner: Arc<std::sync::Mutex<Option<std::sync::Weak<std::fs::File>>>>,
    listeners: Arc<Mutex<BTreeMap<String, JoinHandle<()>>>>,
}
impl Auth {
    #[cfg(test)]
    pub(crate) fn test_unauthed(api: Api) -> Self {
        Self {
            api,
            store: Arc::new(MemoryStore::default()),
            operation_lock: Arc::new(Mutex::new(())),
            store_lock: Arc::new(Mutex::new(())),
            store_owner: Arc::new(std::sync::Mutex::new(None)),
            listeners: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
    /// Identity-only race seam. NativeStore and custom stores always refuse it.
    #[cfg(test)]
    pub(crate) async fn test_fingerprint_identity_drift(
        &self,
        org: &str,
        installation: Option<&str>,
        subject: Option<&str>,
    ) -> Result<()> {
        ensure!(
            self.store.synthetic_fixture(),
            "TEST_SYNTHETIC_STORE_REQUIRED"
        );
        let _guard = self.auth_guard().await?;
        let mut state = self.required().await?;
        if let Some(installation) = installation {
            state.installation_id = installation.into();
        }
        if let Some(subject) = subject {
            state
                .children
                .get_mut(org)
                .ok_or_else(|| anyhow!("ORGANIZATION_NOT_ENROLLED"))?
                .subject = subject.into();
        }
        self.save(&state).await
    }
    #[cfg(test)]
    pub(crate) async fn test_fingerprint_access_near_expiry(&self, org: &str) -> Result<()> {
        ensure!(
            self.store.synthetic_fixture(),
            "SYNTHETIC_AUTH_FIXTURE_REQUIRED"
        );
        let _guard = self.auth_guard().await?;
        let mut state = self.required().await?;
        state
            .children
            .get_mut(org)
            .ok_or_else(|| anyhow!("SYNTHETIC_AUTH_FIXTURE_REQUIRED"))?
            .expires_at = now().saturating_add(59);
        self.save(&state).await
    }
    #[cfg(test)]
    pub(crate) fn test_enrolled(api: Api, org: &str, runner: &str) -> Self {
        let auth = Self::test_unauthed(api);
        let mut state = ProtectedState::fresh();
        state.installation_id = "00000000-0000-4000-8000-000000000001".into();
        state.private_key = [7; 32];
        state.device = Some(Token {
            access: "lmxda_deviceprefix_devicesecret".into(),
            refresh: "lmxdr_deviceprefix_devicerefresh".into(),
            subject: "00000000-0000-4000-8000-000000000002".into(),
            expires_at: now() + 3600,
        });
        state.children.insert(
            org.into(),
            Token {
                access: "lmxr_testprefix_testsecret".into(),
                refresh: "lmxrr_testprefix_testrefresh".into(),
                subject: runner.into(),
                expires_at: now() + 3600,
            },
        );
        state.active_organization = Some(org.into());
        auth.store
            .save(&serde_json::to_vec(&state).expect("in-memory fixture encoding"))
            .expect("in-memory fixture write");
        auth
    }
    /// Synthetic MemoryStore only. No native credential store or serialized
    /// credential bytes escape this fixture; lifecycle tests receive identities
    /// and a whole-record fingerprint through the companion helper.
    #[cfg(test)]
    pub(crate) fn test_persona_lifecycle_fixture(
        api: Api,
        org: &str,
        runner: &str,
        recovery_pending: bool,
    ) -> Self {
        let auth = Self::test_enrolled(api, org, runner);
        let mut state: ProtectedState =
            serde_json::from_slice(&auth.store.load().unwrap().unwrap()).unwrap();
        let delegation = "00000000-0000-4000-8000-000000000003";
        let device = state.device.as_ref().unwrap().subject.clone();
        for (phase, key) in [
            ("grant_pending", "00000000-0000-4000-8000-000000000004"),
            ("refresh_pending", "00000000-0000-4000-8000-000000000005"),
        ] {
            let scopes = json!(["runner.personas.read", "runner.personas.memory.write"]);
            let digest = runner_state::json_digest(
                &json!({"organizationId":org,"requestedScopes":scopes,"idempotencyKey":key}),
            );
            state.persona_state.insert(format!("upgrade:{org}:{key}"), json!({"digest":digest,"phase":phase,"organizationId":org,"runnerId":runner,"deviceId":device,"delegationId":delegation,"requestedScopes":scopes,"idempotencyKey":key}));
        }
        state.persona_state.insert(format!("credential:{org}"), json!({"organizationId":org,"runnerId":runner,"deviceId":device,"delegationId":delegation,"scopes":["runner.personas.read"]}));
        if recovery_pending {
            state.pending = Some(Pending {
                target: Target::ChildRefresh(org.into()),
                route: "v2/delegations/refresh/".into(),
                body: json!({"refreshToken":state.children[org].refresh,"proof":"synthetic-memory-store-proof"}),
                started_at: now(),
                recovery_used: false,
                superseded: None,
            });
        }
        auth.store
            .save(&serde_json::to_vec(&state).unwrap())
            .unwrap();
        auth
    }
    #[cfg(test)]
    pub(crate) fn test_persona_lifecycle_fingerprint(&self, org: &str) -> Value {
        let bytes = self.store.load().unwrap().unwrap();
        let state: ProtectedState = serde_json::from_slice(&bytes).unwrap();
        json!({"protectedDigest":runner_state::digest(&bytes),"installationId":state.installation_id,"deviceId":state.device.as_ref().unwrap().subject,"runnerId":state.children[org].subject,"organizationId":state.active_organization,"delegationId":state.persona_state[&format!("credential:{org}")]["delegationId"],"grantPhases":state.persona_state.values().filter_map(|record| record["phase"].as_str()).collect::<Vec<_>>()})
    }
    #[cfg(test)]
    pub(crate) async fn test_hold_credential_gate(&self) -> tokio::sync::OwnedMutexGuard<()> {
        self.operation_lock.clone().lock_owned().await
    }
    pub fn new(api: Api) -> Result<Self> {
        Ok(Self {
            api,
            store: Arc::new(NativeStore),
            operation_lock: Arc::new(Mutex::new(())),
            store_lock: Arc::new(Mutex::new(())),
            store_owner: Arc::new(std::sync::Mutex::new(None)),
            listeners: Arc::new(Mutex::new(BTreeMap::new())),
        })
    }
    pub(crate) fn retain_store_owner(&self, owner: &Arc<std::fs::File>) {
        // Do not extend ownership merely because an Auth clone survives. Only
        // a started native worker retains the existing singleton through IO.
        *self.store_owner.lock().unwrap() = Some(Arc::downgrade(owner));
    }
    async fn auth_guard(&self) -> Result<tokio::sync::MutexGuard<'_, ()>> {
        tokio::time::timeout(AUTH_LOCK_BUDGET, self.operation_lock.lock())
            .await
            .map_err(|_| anyhow!("AUTH_RECOVERY_PENDING"))
    }
    async fn store_operation<T: Send + 'static>(
        &self,
        mutating: bool,
        operation: impl FnOnce(Arc<dyn Store>) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let deadline = tokio::time::Instant::now() + STORE_IO_BUDGET;
        let io_guard = tokio::time::timeout_at(deadline, self.store_lock.clone().lock_owned())
            .await
            .map_err(|_| anyhow!("STORE_UNAVAILABLE"))?;
        let store = self.store.clone();
        let owner = match self.store_owner.lock().unwrap().as_ref() {
            Some(owner) => Some(
                owner
                    .upgrade()
                    .ok_or_else(|| anyhow!("STORE_UNAVAILABLE"))?,
            ),
            None => None,
        };
        let task = tokio::task::spawn_blocking(move || {
            let _owner = owner;
            // A started OS call cannot be aborted. This guard survives caller
            // timeout/cancellation, so no later store operation can overtake it
            // and repeated calls cannot spawn further blocked OS tasks.
            let _io_guard = io_guard;
            operation(store)
        });
        tokio::time::timeout_at(deadline, task)
            .await
            .map_err(|_| {
                anyhow!(if mutating {
                    "STORE_OPERATION_PENDING"
                } else {
                    "STORE_UNAVAILABLE"
                })
            })?
            .map_err(|_| {
                anyhow!(if mutating {
                    "STORE_OPERATION_PENDING"
                } else {
                    "STORE_UNAVAILABLE"
                })
            })?
    }
    async fn load(&self) -> Result<Option<ProtectedState>> {
        self.store_operation(false, |store| {
            store
                .load()?
                .map(|data| serde_json::from_slice(&data).map_err(|_| anyhow!("STORE_INVALID")))
                .transpose()
        })
        .await
    }
    async fn save(&self, state: &ProtectedState) -> Result<()> {
        let bytes = serde_json::to_vec(state).map_err(|_| anyhow!("STORE_INVALID"))?;
        self.store_operation(true, move |store| store.save(&bytes))
            .await
    }
    async fn required(&self) -> Result<ProtectedState> {
        self.load().await?.ok_or_else(|| anyhow!("AUTH_REQUIRED"))
    }
    async fn revalidate(&self, expected: &ProtectedState) -> Result<()> {
        let current = self.required().await?;
        ensure!(
            serde_json::to_vec(&current)? == serde_json::to_vec(expected)?,
            "AUTH_IDENTITY_CHANGED"
        );
        Ok(())
    }
    fn allowed(state: &ProtectedState) -> Result<()> {
        ensure!(!state.logout_pending, "LOGOUT_PENDING");
        Ok(())
    }
    pub async fn installation_id(&self) -> Result<String> {
        if let Some(state) = self.load().await? {
            return Ok(state.installation_id);
        }
        let _guard = self.auth_guard().await?;
        let state = match self.load().await? {
            Some(state) => state,
            None => {
                let state = ProtectedState::fresh();
                self.save(&state).await?;
                state
            }
        };
        Ok(state.installation_id)
    }
    pub async fn enrolled_organizations(&self) -> Result<Vec<String>> {
        let Some(state) = self.load().await? else {
            return Ok(vec![]);
        };
        Self::allowed(&state)?;
        Ok(state.children.keys().cloned().collect())
    }
    pub async fn status(&self) -> Result<Value> {
        match self.load().await {
            Err(error) => Ok(
                json!({"authenticated":false,"code":credential_store_code(&error),"loginPending":false}),
            ),
            Ok(None) => {
                Ok(json!({"authenticated":false,"code":"AUTH_REQUIRED","loginPending":false}))
            }
            Ok(Some(state)) => Ok(
                json!({"authenticated":state.device.is_some() && !state.logout_pending,"code":if state.logout_pending {"LOGOUT_PENDING"} else if state.pending.is_some() {"AUTH_RECOVERY_PENDING"} else if state.device.is_some() {"AUTHENTICATED"} else {"AUTH_REQUIRED"},"installationId":state.installation_id,"activeOrganization":state.active_organization,"organizations":state.children.keys().collect::<Vec<_>>(),"loginPending":state.login.is_some()}),
            ),
        }
    }
    /// Internal lifecycle observation of an existing operation owner. Ordinary
    /// public snapshots remain store-bounded; this never refreshes or recovers.
    pub(crate) async fn startup_status(&self) -> Result<Value> {
        let _guard =
            tokio::time::timeout(AUTH_STARTUP_OBSERVATION_BUDGET, self.operation_lock.lock())
                .await
                .map_err(|_| anyhow!("AUTH_RECOVERY_PENDING"))?;
        self.status().await
    }
    /// Reconcile the exact durable authentication operation already stored in
    /// the Keychain. This never starts a new login, enrollment, or rotation.
    pub async fn reconcile(&self) -> Result<Value> {
        let _guard = self.auth_guard().await?;
        let mut state = self.required().await?;
        if state.pending.is_some() {
            self.recover(&mut state).await?;
        } else if let Some(login) = state
            .login
            .as_ref()
            .filter(|login| login.received_code.is_some())
        {
            let code = login.received_code.as_deref().unwrap();
            let proof = key_proof(&state.private_key, "browser-exchange", code);
            let body = json!({"transactionId":login.transaction_id,"code":code,"codeVerifier":login.code_verifier,
                "redirectUri":login.redirect_uri,"proof":proof});
            self.begin(
                &mut state,
                Target::BrowserExchange,
                "v2/browser-authorities/exchange/".into(),
                body,
            )
            .await?;
        } else {
            bail!("AUTH_RECOVERY_NOT_REQUIRED")
        }
        Ok(json!({
            "reconciled": true,
            "authenticated": state.device.is_some() && state.pending.is_none(),
            "activeOrganization": state.active_organization,
        }))
    }
    /// A credential-free, local snapshot for clients that need to resume an
    /// existing device flow. This deliberately reads only the runner store: a
    /// connection check must never start a new flow or turn a failed
    /// organization listing into an authentication failure.
    pub async fn connection(
        &self,
        selected_organization: Option<String>,
        active_work: usize,
    ) -> Value {
        let unavailable = |code: &str| {
            json!({
                "schemaVersion":"loomex.runner.connection/v2",
                "state":"credential_store_unavailable",
                "organization":{"status":"organization_required","selected":Value::Null},
                "organizations":[],
                "activeWork":active_work,
                "actions":[],
                "login":Value::Null,
                "details":{"credentialStoreCode":code},
            })
        };
        let stored = match self.load().await {
            Ok(stored) => stored,
            Err(error) => return unavailable(credential_store_code(&error)),
        };
        let Some(state) = stored else {
            return json!({
                "schemaVersion":"loomex.runner.connection/v2",
                "state":"signed_out",
                "organization":{"status":"organization_required","selected":Value::Null},
                "organizations":[],
                "activeWork":active_work,
                "actions":["auth.login"],
                "login":Value::Null,
            });
        };
        let mut callback_unavailable = false;
        if let Some(login) = state.login.as_ref().filter(|login| {
            login.authorization_url.is_some()
                && login.received_code.is_none()
                && state.pending.is_none()
                && login.expires_at > now()
        }) {
            if !self.listeners.lock().await.contains_key(&login.flow_id) {
                if let Some(uri) = login.redirect_uri.as_deref() {
                    let address = uri
                        .trim_start_matches("http://")
                        .trim_end_matches("/oauth/callback");
                    if let Ok(listener) = TcpListener::bind(address).await {
                        self.spawn_callback(listener, login.flow_id.clone()).await;
                    } else {
                        callback_unavailable = true;
                    }
                } else {
                    callback_unavailable = true;
                }
            }
        }
        let mut organizations = state
            .organization_profiles
            .iter()
            .map(|(id, profile)| json!({"id":id,"name":profile.name,"enrolled":profile.enrolled}))
            .collect::<Vec<_>>();
        // Older stores do not contain the cache. Enrolled organizations still
        // remain available to a local connection projection after upgrading.
        for id in state.children.keys() {
            if !state.organization_profiles.contains_key(id) {
                organizations.push(json!({"id":id,"name":Value::Null,"enrolled":true}));
            }
        }
        let selected = selected_organization
            .filter(|id| state.children.contains_key(id))
            .map(|id| json!({"id":id,"name":state.organization_profiles.get(&id).and_then(|profile| profile.name.clone())}));
        let (state_name, actions, login) = if state.logout_pending {
            ("logout_pending", vec!["auth.logout"], Value::Null)
        } else if state.pending.is_some() {
            if let Some(login) = state.login.as_ref().filter(|login| {
                state.device.is_none()
                    && login.transaction_id.is_some()
                    && state.pending.as_ref().is_some_and(|pending| {
                        matches!(
                            pending.target,
                            Target::BrowserExchange | Target::Bootstrap | Target::BrowserCancel
                        )
                    })
            }) {
                (
                    "recovery_pending",
                    vec!["auth.recover", "auth.cancel"],
                    json!({
                        "flowId":flow_identity(&state,login),"authorizationUrl":login.authorization_url,"expiresAt":login.expires_at,
                    }),
                )
            } else {
                (
                    "recovery_pending",
                    vec!["auth.recover", "auth.logout"],
                    Value::Null,
                )
            }
        } else if state.device.is_some() {
            (
                "authenticated",
                vec!["organizations.list", "organizations.select", "auth.logout"],
                Value::Null,
            )
        } else if let Some(login) = state.login.as_ref() {
            if callback_unavailable {
                (
                    "recovery_pending",
                    vec!["auth.cancel"],
                    json!({
                        "flowId":flow_identity(&state,login),"authorizationUrl":login.authorization_url,"expiresAt":login.expires_at,
                    }),
                )
            } else {
                let status = if login.authorization_url.is_none() || login.expires_at <= now() {
                    "verification_expired"
                } else if login.received_code.is_some() {
                    "authentication_completing"
                } else {
                    "browser_pending"
                };
                let actions = if status == "browser_pending" {
                    vec!["auth.cancel"]
                } else if status == "authentication_completing" {
                    vec!["auth.recover"]
                } else if login.transaction_id.is_some() {
                    vec!["auth.cancel"]
                } else {
                    vec!["auth.login"]
                };
                (
                    status,
                    actions,
                    json!({
                        // Existing protected records predate `flow_id`. Derive a
                        // stable, opaque fallback without exposing their original
                        // idempotency key or device code.
                        "flowId":flow_identity(&state, login),
                        "authorizationUrl":login.authorization_url,
                        "expiresAt":login.expires_at,
                    }),
                )
            }
        } else {
            ("signed_out", vec!["auth.login"], Value::Null)
        };
        json!({
            "schemaVersion":"loomex.runner.connection/v2",
            "state":state_name,
            "organization":{"status":if selected.is_some(){"connected"}else{"organization_required"},"selected":selected},
            "organizations":organizations,
            "activeWork":active_work,
            "actions":actions,
            "login":login,
        })
    }
    pub async fn login(&self, runner_name: &str, key: &str) -> Result<Value> {
        ensure!((16..=256).contains(&key.len()), "INVALID_IDEMPOTENCY_KEY");
        ensure!(!runner_name.trim().is_empty(), "RUNNER_NAME_REQUIRED");
        let _guard = self.auth_guard().await?;
        let mut state = self.load().await?.unwrap_or_else(ProtectedState::fresh);
        Self::allowed(&state)?;
        if state.pending.is_some() {
            self.recover(&mut state).await?;
        }
        if state.device.is_some() {
            return Ok(json!({"status":"authenticated","authenticated":true}));
        }
        if let Some(login) = &state.login {
            ensure!(
                login.key != key || login.runner_name == runner_name,
                "IDEMPOTENCY_CONFLICT"
            );
            if login.key == key && login.authorization_url.is_some() && login.expires_at > now() {
                return Ok(login_projection(login));
            }
            ensure!(
                login.key == key || login.expires_at <= now() || login.authorization_url.is_none(),
                "LOGIN_ALREADY_PENDING"
            );
        }
        let reused = state
            .login
            .as_ref()
            .filter(|login| login.key == key && login.redirect_uri.is_some())
            .cloned();
        let (login, listener) = if let Some(login) = reused {
            let listener = if login.expires_at <= now()
                || self.listeners.lock().await.contains_key(&login.flow_id)
            {
                None
            } else {
                Some(
                    TcpListener::bind(
                        login
                            .redirect_uri
                            .as_deref()
                            .unwrap()
                            .trim_start_matches("http://")
                            .trim_end_matches("/oauth/callback"),
                    )
                    .await
                    .map_err(|_| anyhow!("LOGIN_CALLBACK_UNAVAILABLE"))?,
                )
            };
            (login, listener)
        } else {
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .map_err(|_| anyhow!("LOGIN_CALLBACK_UNAVAILABLE"))?;
            let redirect_uri = format!("http://{}/oauth/callback", listener.local_addr()?);
            let random = |length| {
                let mut bytes = vec![0u8; length];
                rand::rngs::OsRng.fill_bytes(&mut bytes);
                URL_SAFE_NO_PAD.encode(bytes)
            };
            (
                Login {
                    key: key.into(),
                    runner_name: runner_name.into(),
                    flow_id: uuid::Uuid::new_v4().to_string(),
                    expires_at: now() + 600,
                    authorization_url: None,
                    transaction_id: None,
                    redirect_uri: Some(redirect_uri),
                    browser_state: Some(random(32)),
                    code_verifier: Some(random(32)),
                    received_code: None,
                },
                Some(listener),
            )
        };
        state.login = Some(login.clone());
        self.save(&state).await?;
        if let Some(listener) = listener {
            self.spawn_callback(listener, login.flow_id.clone()).await;
        }
        let public_key = URL_SAFE_NO_PAD.encode(
            SigningKey::from_bytes(&state.private_key)
                .verifying_key()
                .as_bytes(),
        );
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(
            login.code_verifier.as_ref().unwrap().as_bytes(),
        ));
        let data = self.api.request("POST", "v2/browser-authorities/start/", Some(json!({
            "installId":state.installation_id, "runnerName":runner_name, "publicKey":public_key,
            "clientId":"loomex-native/v1", "redirectUri":login.redirect_uri,
            "state":login.browser_state, "codeChallenge":challenge,
        })), None, Some(key)).await?;
        self.revalidate(&state).await?;
        let uri = self.api.browser_authorization_uri(
            &field(&data, "authorizationPath")?,
            &field(&data, "transactionId")?,
            login.browser_state.as_deref().unwrap(),
        )?;
        let login = state
            .login
            .as_mut()
            .ok_or_else(|| anyhow!("LOGIN_REQUIRED"))?;
        login.authorization_url = Some(uri);
        login.transaction_id = Some(field(&data, "transactionId")?);
        login.expires_at = data["expiresAt"]
            .as_u64()
            .ok_or_else(|| anyhow!("INVALID_API_RESPONSE"))?;
        if let Some(status) = data.get("status") {
            ensure!(
                matches!(
                    status.as_str(),
                    Some("pending" | "approved" | "consumed" | "denied" | "revoked" | "expired")
                ),
                "INVALID_API_RESPONSE"
            );
            if status != "pending" {
                // Start recovery returns a transaction reference, never new
                // approval authority. A decided flow can only be reconciled or
                // proof-canceled, even if its bootstrap deadline is still live.
                login.expires_at = 0;
            }
        }
        self.save(&state).await?;
        Ok(login_projection(state.login.as_ref().unwrap()))
    }

    /// Launch only the authorization URL sealed for the current pending flow.
    /// The URL is never accepted from the caller, and opening it does not prove
    /// authentication or approval. The callback remains runner-owned.
    pub async fn open_browser(&self, flow_id: &str) -> Result<Value> {
        self.open_browser_with(flow_id, |url| async move { launch_browser(&url).await })
            .await
    }

    async fn open_browser_with<F, Fut>(&self, flow_id: &str, opener: F) -> Result<Value>
    where
        F: FnOnce(String) -> Fut,
        Fut: Future<Output = Result<()>>,
    {
        let _guard = self.auth_guard().await?;
        let state = self.required().await?;
        Self::allowed(&state)?;
        ensure!(state.device.is_none(), "AUTH_ALREADY_COMPLETED");
        let login = state
            .login
            .as_ref()
            .ok_or_else(|| anyhow!("LOGIN_REQUIRED"))?;
        ensure!(
            flow_identity(&state, login) == flow_id,
            "LOGIN_FLOW_MISMATCH"
        );
        ensure!(login.expires_at > now(), "AUTH_EXPIRED");
        ensure!(login.received_code.is_none(), "AUTH_PENDING_COMPLETION");
        let url = login
            .authorization_url
            .as_ref()
            .ok_or_else(|| anyhow!("BROWSER_LINK_UNAVAILABLE"))?;
        let expected = self.api.browser_authorization_uri(
            "/api/v1/runner-control/runner/v2/browser-authorities/authorize/",
            login
                .transaction_id
                .as_deref()
                .ok_or_else(|| anyhow!("BROWSER_LINK_UNAVAILABLE"))?,
            login
                .browser_state
                .as_deref()
                .ok_or_else(|| anyhow!("BROWSER_LINK_UNAVAILABLE"))?,
        )?;
        ensure!(url == &expected, "INVALID_AUTHORIZATION_URI");
        opener(url.clone()).await?;
        Ok(json!({"status":"launch_requested","flowId":flow_id}))
    }

    async fn spawn_callback(&self, listener: TcpListener, flow_id: String) {
        let auth = self.clone();
        let id = flow_id.clone();
        let task = tokio::spawn(async move {
            loop {
                let remaining = {
                    let Ok(Some(state)) = auth.load().await else {
                        break;
                    };
                    let Some(login) = state.login.as_ref().filter(|login| login.flow_id == id)
                    else {
                        break;
                    };
                    login.expires_at.saturating_sub(now())
                };
                if remaining == 0 {
                    break;
                }
                let Ok(Ok((mut socket, _))) = tokio::time::timeout(
                    std::time::Duration::from_secs(remaining.min(30)),
                    listener.accept(),
                )
                .await
                else {
                    continue;
                };
                let mut buffer = [0u8; 8192];
                let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
                let mut size = 0;
                while size < buffer.len()
                    && !buffer[..size].windows(4).any(|part| part == b"\r\n\r\n")
                {
                    let Ok(Ok(read)) =
                        tokio::time::timeout_at(deadline, socket.read(&mut buffer[size..])).await
                    else {
                        break;
                    };
                    if read == 0 {
                        break;
                    }
                    size += read;
                }
                let target = (buffer[..size].windows(4).any(|part| part == b"\r\n\r\n"))
                    .then_some(size)
                    .and_then(|len| {
                        let request = std::str::from_utf8(&buffer[..len]).ok()?;
                        let expected_host = format!("Host: {}", listener.local_addr().ok()?);
                        if !request
                            .lines()
                            .any(|line| line.eq_ignore_ascii_case(&expected_host))
                        {
                            return None;
                        }
                        let mut parts = request.lines().next()?.split_whitespace();
                        (parts.next() == Some("GET")).then_some(parts.next()?)
                    });
                let callback = target.and_then(|target| {
                    let url = url::Url::parse(&format!("http://127.0.0.1{target}")).ok()?;
                    if url.path() != "/oauth/callback" {
                        return None;
                    }
                    let mut query = BTreeMap::new();
                    for (name, value) in url.query_pairs() {
                        if !matches!(name.as_ref(), "state" | "code" | "error")
                            || query.insert(name, value).is_some()
                        {
                            return None;
                        }
                    }
                    if query.contains_key("code") == query.contains_key("error") {
                        return None;
                    }
                    Some((
                        query.get("state")?.to_string(),
                        query.get("code").map(ToString::to_string),
                        query.get("error").map(ToString::to_string),
                    ))
                });
                let denied = callback
                    .as_ref()
                    .is_some_and(|(_, _, error)| error.as_deref() == Some("access_denied"));
                let outcome = if let Some((state, code, error)) = callback {
                    auth.complete_browser_callback(&id, &state, code.as_deref(), error.as_deref())
                        .await
                } else {
                    Err(anyhow!("INVALID_CALLBACK"))
                };
                let recoverable = outcome.is_err()
                    && auth.load().await.ok().flatten().is_some_and(|state| {
                        state.login.as_ref().is_some_and(|login| {
                            login.flow_id == id && login.received_code.is_some()
                        }) && state.pending.as_ref().is_some_and(|pending| {
                            matches!(pending.target, Target::BrowserExchange | Target::Bootstrap)
                        })
                    });
                let result = if denied && outcome.is_ok() {
                    BrowserCallbackOutcome::Declined
                } else if outcome.is_ok() {
                    BrowserCallbackOutcome::SignedIn
                } else if recoverable {
                    BrowserCallbackOutcome::RecoveryRequired
                } else {
                    BrowserCallbackOutcome::Invalid
                };
                let response = browser_callback_response(result);
                let _ = socket.write_all(response.as_bytes()).await;
                if outcome.is_ok() || recoverable {
                    break;
                }
            }
            auth.listeners.lock().await.remove(&id);
        });
        self.listeners.lock().await.insert(flow_id, task);
    }
    async fn complete_browser_callback(
        &self,
        flow_id: &str,
        state_value: &str,
        code: Option<&str>,
        error: Option<&str>,
    ) -> Result<()> {
        let _guard = self.auth_guard().await?;
        let mut state = self.required().await?;
        let login = state
            .login
            .as_ref()
            .ok_or_else(|| anyhow!("LOGIN_REQUIRED"))?;
        ensure!(
            login.flow_id == flow_id
                && login.expires_at > now()
                && login.browser_state.as_deref() == Some(state_value),
            "LOGIN_FLOW_MISMATCH"
        );
        if error == Some("access_denied") {
            state.login = None;
            self.save(&state).await?;
            return Ok(());
        }
        let code = code
            .filter(|code| (32..=256).contains(&code.len()))
            .ok_or_else(|| anyhow!("INVALID_CALLBACK"))?;
        ensure!(login.received_code.is_none(), "LOGIN_CALLBACK_REPLAY");
        state.login.as_mut().unwrap().received_code = Some(code.into());
        self.save(&state).await?;
        let login = state.login.as_ref().unwrap();
        let proof = key_proof(&state.private_key, "browser-exchange", code);
        let body = json!({"transactionId":login.transaction_id,"code":code,"codeVerifier":login.code_verifier,
            "redirectUri":login.redirect_uri,"proof":proof});
        self.begin(
            &mut state,
            Target::BrowserExchange,
            "v2/browser-authorities/exchange/".into(),
            body,
        )
        .await
    }
    pub async fn cancel_login(&self, flow_id: &str) -> Result<Value> {
        let _guard = self.auth_guard().await?;
        let mut state = self.required().await?;
        self.cancel_login_locked(&mut state, flow_id).await?;
        if let Some(listener) = self.listeners.lock().await.remove(flow_id) {
            listener.abort()
        }
        Ok(json!({"canceled":true}))
    }
    async fn cancel_login_locked(&self, state: &mut ProtectedState, flow_id: &str) -> Result<()> {
        ensure!(state.device.is_none(), "AUTH_ALREADY_COMPLETED");
        let login = state
            .login
            .as_ref()
            .ok_or_else(|| anyhow!("LOGIN_REQUIRED"))?;
        ensure!(
            flow_identity(state, login) == flow_id,
            "LOGIN_FLOW_MISMATCH"
        );
        ensure!(login.transaction_id.is_some(), "AUTH_RECOVERY_PENDING");
        if state
            .pending
            .as_ref()
            .is_some_and(|pending| matches!(pending.target, Target::BrowserCancel))
        {
            return self.recover(state).await;
        }
        ensure!(
            state.pending.as_ref().is_none_or(|pending| matches!(
                pending.target,
                Target::BrowserExchange | Target::Bootstrap
            )),
            "AUTH_RECOVERY_PENDING"
        );
        let revoke_approved =
            state.pending.is_some() || login.received_code.is_some() || login.expires_at <= now();
        let state_value = login
            .browser_state
            .as_deref()
            .ok_or_else(|| anyhow!("LOGIN_REQUIRED"))?;
        let purpose = if revoke_approved {
            "browser-cancel-recovery"
        } else {
            "browser-cancel"
        };
        let proof = key_proof(&state.private_key, purpose, state_value);
        let body = json!({"transactionId":login.transaction_id,"state":state_value,"proof":proof,
            "revokeApproved":revoke_approved});
        // Persist the cancellation intent and its displaced operation together
        // before transmission. Ambiguity always recovers this exact intent.
        state.pending = Some(Pending {
            target: Target::BrowserCancel,
            route: "v2/browser-authorities/cancel/".into(),
            body,
            started_at: now(),
            recovery_used: false,
            superseded: state.pending.take().map(Box::new),
        });
        self.save(state).await?;
        self.transmit(state, false).await
    }
    pub async fn organizations(&self) -> Result<Value> {
        let _guard = self.auth_guard().await?;
        let mut state = self.required().await?;
        self.ensure_device(&mut state).await?;
        let credential = state.device.as_ref().unwrap().signed(&state);
        let data = self
            .api
            .request("GET", "v2/organizations/", None, Some(&credential), None)
            .await?;
        self.revalidate(&state).await?;
        let mut profiles = BTreeMap::new();
        let orgs = data["organizations"]
            .as_array()
            .ok_or_else(|| anyhow!("INVALID_API_RESPONSE"))?
            .iter()
            .map(|org| {
                let id = field(org, "id")?;
                let name = org["name"]
                    .as_str()
                    .filter(|name| !name.is_empty() && name.len() <= 512)
                    .map(str::to_owned);
                let slug = org["slug"]
                    .as_str()
                    .filter(|slug| !slug.is_empty() && slug.len() <= 512)
                    .map(str::to_owned);
                let enrolled = org["enrolled"].as_bool().unwrap_or(false);
                profiles.insert(id.clone(), OrganizationProfile { name, slug, enrolled });
                Ok(json!({"id":id,"name":org["name"],"slug":org["slug"],"enrolled":org["enrolled"],"runner":org.get("runner").filter(|r|!r.is_null()).map(|r|json!({"id":r["id"],"name":r["name"]}))}))
            })
            .collect::<Result<Vec<_>>>()?;
        // Replace only after parsing a complete, successful response. A list
        // failure therefore leaves the existing local auth projection intact.
        state.organization_profiles = profiles;
        self.save(&state).await?;
        Ok(json!({"organizations":orgs}))
    }
    pub async fn select(&self, org: &str, key: &str) -> Result<Value> {
        ensure!((16..=256).contains(&key.len()), "INVALID_IDEMPOTENCY_KEY");
        ensure!(
            !org.is_empty()
                && org
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_'),
            "INVALID_ORGANIZATION_ID"
        );
        let _guard = self.auth_guard().await?;
        let mut state = self.required().await?;
        self.ensure_device(&mut state).await?;
        if !state.children.contains_key(org) {
            self.begin(
                &mut state,
                Target::Enroll(org.into()),
                format!("v2/organizations/{org}/enroll/"),
                json!({"idempotencyKey":key}),
            )
            .await?;
        }
        ensure!(
            state.children.contains_key(org),
            "ENROLLMENT_CREDENTIALS_UNAVAILABLE"
        );
        state
            .organization_profiles
            .entry(org.into())
            .and_modify(|profile| profile.enrolled = true)
            .or_insert(OrganizationProfile {
                name: None,
                slug: None,
                enrolled: true,
            });
        state.active_organization = Some(org.into());
        self.save(&state).await?;
        Ok(json!({"organizationId":org,"selected":true,"enrolled":true}))
    }
    pub async fn credential(&self, org: &str) -> Result<SignedCredential> {
        let _guard = self.auth_guard().await?;
        let mut state = self.required().await?;
        Self::allowed(&state)?;
        if state.pending.is_some() {
            self.recover(&mut state).await?;
        }
        for _ in 0..2 {
            let child = state
                .children
                .get(org)
                .ok_or_else(|| anyhow!("ORGANIZATION_NOT_ENROLLED"))?;
            if child.usable() {
                return Ok(child.signed(&state));
            }
            let refresh = child.refresh.clone();
            let proof = key_proof(&state.private_key, "refresh", &refresh);
            self.begin(
                &mut state,
                Target::ChildRefresh(org.into()),
                "v1/delegations/refresh/".into(),
                json!({"refreshToken":refresh,"proof":proof}),
            )
            .await?;
        }
        bail!("AUTH_EXPIRED")
    }
    /// Returns the already-enrolled local child identity without refreshing,
    /// recovering, persisting, or contacting the backend.
    pub async fn current_child_identity(&self, org: &str) -> Result<(String, String)> {
        // Preserve FIFO ordering with owner mutations queued during refresh.
        // A raw store snapshot can overtake the already admitted subject change.
        let _guard = self.auth_guard().await?;
        let state = self.required().await?;
        Self::allowed(&state)?;
        ensure!(state.pending.is_none(), "AUTH_RECONCILIATION_REQUIRED");
        let child = state
            .children
            .get(org)
            .ok_or_else(|| anyhow!("ORGANIZATION_NOT_ENROLLED"))?;
        ensure!(child.usable(), "AUTH_REQUIRED");
        Ok((child.subject.clone(), state.installation_id))
    }
    /// Explicit additive grant upgrade. The old child remains enrolled and usable
    /// throughout grant ambiguity. Rotation is separately proof-journaled.
    pub async fn scope_upgrade(&self, org: &str, scopes: &Value, key: &str) -> Result<Value> {
        uuid::Uuid::parse_str(org).map_err(|_| anyhow!("INVALID_REQUEST"))?;
        uuid::Uuid::parse_str(key).map_err(|_| anyhow!("INVALID_REQUEST"))?;
        let requested = scopes
            .as_array()
            .ok_or_else(|| anyhow!("INVALID_REQUEST"))?;
        ensure!(
            !requested.is_empty()
                && requested
                    .iter()
                    .all(|scope| scope.as_str().is_some_and(persona_scope)),
            "INVALID_REQUEST"
        );
        let _guard = self.auth_guard().await?;
        let mut state = self.required().await?;
        Self::allowed(&state)?;
        let journal_key = format!("upgrade:{org}:{key}");
        let digest = runner_state::json_digest(
            &json!({"organizationId":org,"requestedScopes":scopes,"idempotencyKey":key}),
        );
        if let Some(record) = state.persona_state.get(&journal_key) {
            ensure!(record["digest"] == digest, "IDEMPOTENCY_CONFLICT");
            if record["phase"] == "verified" || record["phase"] == "denied" {
                ensure!(
                    state
                        .device
                        .as_ref()
                        .is_some_and(|device| record["deviceId"] == device.subject)
                        && state
                            .children
                            .get(org)
                            .is_some_and(|child| record["runnerId"] == child.subject),
                    "AUTH_IDENTITY_CHANGED"
                );
                return Ok(record["result"].clone());
            }
        } else {
            self.ensure_device(&mut state).await?;
            let child = state
                .children
                .get(org)
                .ok_or_else(|| anyhow!("ORGANIZATION_NOT_ENROLLED"))?;
            let runner_id = child.subject.clone();
            let credential = state.device.as_ref().unwrap().signed(&state);
            // Existing attachment discovery does not issue a replacement child.
            let enrolled = self
                .api
                .request(
                    "POST",
                    &format!("v2/organizations/{org}/enroll/"),
                    Some(json!({"idempotencyKey":key})),
                    Some(&credential),
                    Some(key),
                )
                .await?;
            self.revalidate(&state).await?;
            ensure!(
                enrolled["runner"]["id"] == runner_id,
                "AUTH_IDENTITY_CHANGED"
            );
            let delegation = field(&enrolled["child"], "delegationId")?;
            let device = state.device.as_ref().unwrap().subject.clone();
            if let Some(id) = enrolled.get("deviceId") {
                ensure!(id == &json!(device), "AUTH_IDENTITY_CHANGED");
            }
            state.persona_state.insert(journal_key.clone(),json!({"digest":digest,"phase":"grant_pending","organizationId":org,"runnerId":runner_id,"deviceId":device,"delegationId":delegation,"requestedScopes":scopes,"idempotencyKey":key}));
            self.save(&state).await?;
        }
        let mut record = state.persona_state[&journal_key].clone();
        ensure!(
            record["organizationId"] == org
                && record["requestedScopes"] == *scopes
                && record["idempotencyKey"] == key,
            "IDEMPOTENCY_CONFLICT"
        );
        ensure!(
            state
                .device
                .as_ref()
                .is_some_and(|device| record["deviceId"] == device.subject)
                && state
                    .children
                    .get(org)
                    .is_some_and(|child| record["runnerId"] == child.subject),
            "AUTH_IDENTITY_CHANGED"
        );
        if record["phase"] == "grant_pending" {
            self.ensure_device(&mut state).await?;
            let credential = state.device.as_ref().unwrap().signed(&state);
            ensure!(
                record["deviceId"] == credential.subject,
                "AUTH_IDENTITY_CHANGED"
            );
            let receipt = self.api.request("POST",&format!("v2/device-authorities/organizations/{org}/scope-upgrade/"),Some(json!({"delegationId":record["delegationId"],"requestedScopes":scopes,"idempotencyKey":key})),Some(&credential),Some(key)).await.map_err(|error| if error.retryable { anyhow!("NETWORK_AMBIGUOUS") } else { error.into() })?;
            self.revalidate(&state).await?;
            for identity in ["deviceId", "runnerId", "delegationId", "organizationId"] {
                ensure!(
                    receipt[identity] == record[identity],
                    "AUTH_IDENTITY_CHANGED"
                );
            }
            ensure!(
                receipt["requestedScopes"] == *scopes,
                "INVALID_API_RESPONSE"
            );
            if receipt["status"] == "denied" {
                record["phase"] = json!("denied");
                record["result"] = json!({"organizationId":org,"runnerId":record["runnerId"],"delegationId":record["delegationId"],"deviceId":record["deviceId"],"scopes":receipt["grantedScopes"],"status":"denied"});
                state.persona_state.insert(journal_key, record.clone());
                self.save(&state).await?;
                return Ok(record["result"].clone());
            }
            ensure!(
                receipt["status"] == "granted" && receipt["refreshRequired"] == true,
                "INVALID_API_RESPONSE"
            );
            record["phase"] = json!("refresh_pending");
            state
                .persona_state
                .insert(journal_key.clone(), record.clone());
            self.save(&state).await?;
        }
        // An interrupted refresh is recovered using its original refresh/proof.
        // One additional rotation may be necessary when recovery returns a
        // pre-upgrade access token; both rotations retain the same child.
        if state.pending.is_some() {
            self.recover(&mut state).await?;
        }
        // An already completed rotation may come from an older server that
        // omitted attachment metadata. Verify current signed authority before
        // doing any further rotation or settling this original receipt.
        let metadata = self
            .verified_scope_metadata(&mut state, org, Some(&record))
            .await?;
        ensure!(
            requested.iter().all(|scope| metadata["scopes"]
                .as_array()
                .is_some_and(|granted| granted.contains(scope))),
            "AUTH_SCOPE_VERIFICATION_REQUIRED"
        );
        record["phase"] = json!("verified");
        record["result"] = metadata.clone();
        state.persona_state.insert(journal_key, record);
        self.save(&state).await?;
        Ok(metadata)
    }
    pub async fn scope_status(&self, org: &str) -> Result<Value> {
        uuid::Uuid::parse_str(org).map_err(|_| anyhow!("INVALID_REQUEST"))?;
        let _guard = self.auth_guard().await?;
        let mut state = self.required().await?;
        Self::allowed(&state)?;
        if state.pending.is_some() {
            self.recover(&mut state).await?;
        }
        self.verified_scope_metadata(&mut state, org, None).await
    }
    /// Caller owns the auth operation gate and has recovered any original
    /// pending request. This never upgrades grants; it rotates only an expired
    /// child or a token proven older than its current Persona grant.
    async fn verified_scope_metadata(
        &self,
        state: &mut ProtectedState,
        org: &str,
        expected_binding: Option<&Value>,
    ) -> Result<Value> {
        // A local metadata cache is not current grant authority. Self is a
        // signed, read-only discovery of the existing child attachment.
        for attempt in 0..2 {
            let child = state
                .children
                .get(org)
                .ok_or_else(|| anyhow!("ORGANIZATION_NOT_ENROLLED"))?;
            if !child.usable() {
                self.refresh_child(state, org).await?;
            }
            let child = &state.children[org];
            let credential = child.signed(state);
            let response = self
                .api
                .request("GET", "v1/self/", None, Some(&credential), None)
                .await;
            self.revalidate(state).await?;
            let data = response?;
            let context = data
                .get("scopeContext")
                .filter(|context| context.is_object())
                .ok_or_else(|| anyhow!("AUTH_SCOPE_VERIFICATION_REQUIRED"))?;
            ensure!(context["organizationId"] == org, "AUTH_IDENTITY_CHANGED");
            let granted = context["grantedScopes"]
                .as_array()
                .filter(|scopes| scopes.iter().all(Value::is_string))
                .ok_or_else(|| anyhow!("INVALID_API_RESPONSE"))?;
            let metadata = persona_credential_metadata(
                &json!({"organizationId":context["organizationId"],"runnerId":context["runnerId"],"deviceId":context["deviceId"],"delegationId":context["delegationId"],"scopes":context["effectiveTokenScopes"]}),
                org,
            )?;
            ensure!(
                data["runner"]["id"] == child.subject
                    && data["runner"]["organizationId"] == org
                    && metadata["runnerId"] == child.subject
                    && state
                        .device
                        .as_ref()
                        .is_some_and(|device| metadata["deviceId"] == device.subject),
                "AUTH_IDENTITY_CHANGED"
            );
            if let Some(cached) = state.persona_state.get(&format!("credential:{org}")) {
                for identity in ["organizationId", "runnerId", "deviceId", "delegationId"] {
                    ensure!(
                        cached[identity] == metadata[identity],
                        "AUTH_IDENTITY_CHANGED"
                    );
                }
            }
            // Fence the original receipt before a stale-token rotation. A
            // current attachment for a different delegation cannot settle or
            // mutate this earlier upgrade intent.
            if let Some(expected) = expected_binding {
                for identity in ["organizationId", "runnerId", "deviceId", "delegationId"] {
                    ensure!(
                        metadata[identity] == expected[identity],
                        "AUTH_IDENTITY_CHANGED"
                    );
                }
            }
            ensure!(
                data["tokenScopes"] == metadata["scopes"],
                "INVALID_API_RESPONSE"
            );
            // A grant can have been explicitly upgraded while this access token
            // predates it. Only ordinary rotation is permitted by a status read.
            let effective = metadata["scopes"].as_array().unwrap();
            let mut normalized_grant = granted.clone();
            for (source, implied) in [
                ("runner.personas.chat", "runner.personas.read"),
                (
                    "runner.personas.memory.write",
                    "runner.personas.memory.read",
                ),
            ] {
                if granted.contains(&json!(source)) && !normalized_grant.contains(&json!(implied)) {
                    normalized_grant.push(json!(implied));
                }
            }
            ensure!(
                effective
                    .iter()
                    .all(|scope| !scope.as_str().is_some_and(persona_scope)
                        || normalized_grant.contains(scope)),
                "INVALID_API_RESPONSE"
            );
            let token_stale = normalized_grant.iter().any(|scope| {
                scope.as_str().is_some_and(persona_scope) && !effective.contains(scope)
            });
            if token_stale {
                if attempt == 0 {
                    self.refresh_child(state, org).await?;
                    continue;
                }
                bail!("AUTH_SCOPE_VERIFICATION_REQUIRED");
            }
            let mut result = metadata;
            result["status"] = json!("verified");
            return Ok(result);
        }
        bail!("AUTH_SCOPE_VERIFICATION_REQUIRED")
    }
    async fn refresh_child(&self, state: &mut ProtectedState, org: &str) -> Result<()> {
        let child = state
            .children
            .get(org)
            .ok_or_else(|| anyhow!("ORGANIZATION_NOT_ENROLLED"))?;
        let refresh = child.refresh.clone();
        let proof = key_proof(&state.private_key, "refresh", &refresh);
        self.begin(
            state,
            Target::ChildRefresh(org.into()),
            "v1/delegations/refresh/".into(),
            json!({"refreshToken":refresh,"proof":proof}),
        )
        .await
    }
    pub async fn logout(&self) -> Result<Value> {
        let _guard = self.auth_guard().await?;
        self.logout_locked().await
    }
    pub async fn offline_logout(&self) -> Result<Value> {
        let _guard = self.auth_guard().await?;
        if let Some(mut state) = self.load().await? {
            if state.device.is_none() && (state.pending.is_some() || !state.children.is_empty()) {
                if state
                    .login
                    .as_ref()
                    .is_some_and(|login| login.transaction_id.is_some())
                    && state.pending.as_ref().is_some_and(|pending| {
                        matches!(
                            pending.target,
                            Target::BrowserExchange | Target::Bootstrap | Target::BrowserCancel
                        )
                    })
                {
                    // Explicit uninstall/logout may abandon this browser-owned
                    // authority without recovering expired issuance material.
                    // Deletion still follows confirmed remote revocation.
                    let result = self.logout_locked().await?;
                    self.store_operation(true, |store| store.delete()).await?;
                    return Ok(result);
                }
                // A lost bootstrap reply can represent an active remote authority.
                // Preserve its only proof and reconcile through the existing one-use
                // recovery protocol before claiming revocation or deleting anything.
                state.logout_pending = true;
                self.save(&state).await?;
                if !state.pending.as_ref().is_some_and(|pending| {
                    matches!(pending.target, Target::Bootstrap) && pending.can_recover()
                }) {
                    bail!("AUTH_RECONCILIATION_REQUIRED");
                }
                self.recover(&mut state)
                    .await
                    .map_err(|_| anyhow!("AUTH_RECONCILIATION_REQUIRED"))?;
                ensure!(state.device.is_some(), "AUTH_RECONCILIATION_REQUIRED");
            }
        }
        let result = self.logout_locked().await?;
        self.store_operation(true, |store| store.delete()).await?;
        Ok(result)
    }
    async fn logout_locked(&self) -> Result<Value> {
        let Some(mut state) = self.load().await? else {
            return Ok(json!({"revoked":true,"alreadyLoggedOut":true}));
        };
        if state.device.is_none() {
            if let Some(login) = state
                .login
                .as_ref()
                .filter(|login| login.transaction_id.is_some())
            {
                let flow = login.flow_id.clone();
                self.cancel_login_locked(&mut state, &flow).await?;
                if let Some(listener) = self.listeners.lock().await.remove(&flow) {
                    listener.abort()
                }
            }
        }
        if let Some(device) = state.device.as_ref() {
            // Logout accepts the historical signed access token, including after
            // expiry or revocation. Never rotate credentials before recording intent.
            state.logout_pending = true;
            self.save(&state).await?;
            let credential = device.signed(&state);
            self.api
                .request(
                    "POST",
                    "v2/device-authorities/logout/",
                    Some(json!({})),
                    Some(&credential),
                    None,
                )
                .await?;
        }
        self.revalidate(&state).await?;
        state.device = None;
        state.children.clear();
        state.organization_profiles.clear();
        state.persona_state.clear();
        state.pending = None;
        state.login = None;
        state.logout_pending = false;
        state.active_organization = None;
        self.save(&state).await?;
        Ok(json!({"revoked":true}))
    }
    async fn ensure_device(&self, state: &mut ProtectedState) -> Result<()> {
        Self::allowed(state)?;
        if state.pending.is_some() {
            self.recover(state).await?;
        }
        for _ in 0..2 {
            let token = state
                .device
                .as_ref()
                .ok_or_else(|| anyhow!("AUTH_REQUIRED"))?;
            if token.usable() {
                return Ok(());
            }
            let refresh = token.refresh.clone();
            let proof = key_proof(&state.private_key, "device-refresh", &refresh);
            self.begin(
                state,
                Target::DeviceRefresh,
                "v2/device-authorities/refresh/".into(),
                json!({"refreshToken":refresh,"proof":proof}),
            )
            .await?;
        }
        bail!("AUTH_EXPIRED")
    }
    async fn begin(
        &self,
        state: &mut ProtectedState,
        target: Target,
        route: String,
        body: Value,
    ) -> Result<()> {
        ensure!(state.pending.is_none(), "AUTH_RECOVERY_PENDING");
        state.pending = Some(Pending {
            target,
            route,
            body,
            started_at: now(),
            recovery_used: false,
            superseded: None,
        });
        self.save(state).await?;
        match self.transmit(state, false).await {
            Ok(()) => Ok(()),
            Err(error)
                if error
                    .downcast_ref::<crate::api::ApiError>()
                    .is_some_and(|e| e.retryable) =>
            {
                self.recover(state).await
            }
            Err(error) => Err(error),
        }
    }
    async fn recover(&self, state: &mut ProtectedState) -> Result<()> {
        let pending = state
            .pending
            .as_mut()
            .ok_or_else(|| anyhow!("AUTH_REQUIRED"))?;
        ensure!(pending.can_recover(), "AUTH_RECOVERY_EXHAUSTED");
        pending.recovery_used = true;
        self.save(state).await?;
        self.transmit(state, true).await
    }
    async fn transmit(&self, state: &mut ProtectedState, recovery: bool) -> Result<()> {
        let pending = state
            .pending
            .clone()
            .ok_or_else(|| anyhow!("AUTH_REQUIRED"))?;
        let mut body = pending.body.clone();
        if recovery {
            body["recovery"] = json!(true);
        }
        let credential = if matches!(pending.target, Target::Enroll(_)) {
            let device = state
                .device
                .as_ref()
                .ok_or_else(|| anyhow!("AUTH_REQUIRED"))?;
            if !device.usable() {
                if !recovery {
                    // The initial enrollment has not been transmitted. Drop
                    // only this local unsent record so the next select can
                    // refresh the device before starting the same request.
                    state.pending = None;
                    self.save(state).await?;
                }
                bail!("AUTH_EXPIRED")
            }
            Some(device.signed(state))
        } else {
            None
        };
        let response = self
            .api
            .request(
                "POST",
                &pending.route,
                Some(body),
                credential.as_ref(),
                None,
            )
            .await;
        // The operation owner never releases its gate across transport. Re-read
        // the durable generation before adopting either success or rejection.
        self.revalidate(state).await?;
        let data = match response {
            Ok(data) => data,
            Err(error) => {
                // A definite enrollment rejection issued no recoverable child
                // credential. It must not fence unrelated enrolled organizations.
                // Keep ambiguous transport failures and rotation records protected.
                if matches!(pending.target, Target::Enroll(_)) && !error.retryable {
                    state.pending = None;
                    self.save(state).await?;
                }
                return Err(error.into());
            }
        };
        match pending.target {
            Target::BrowserExchange => {
                let grant = field(&data, "bootstrapGrant")?;
                let proof = key_proof(&state.private_key, "device-bootstrap", &grant);
                state.pending = Some(Pending {
                    target: Target::Bootstrap,
                    route: "v2/device-authorities/bootstrap/".into(),
                    body: json!({"bootstrapGrant":grant,"proof":proof}),
                    started_at: now(),
                    recovery_used: false,
                    superseded: None,
                });
                self.save(state).await?;
                return Box::pin(self.transmit(state, false)).await;
            }
            Target::BrowserCancel => {
                if data["canceled"] != true {
                    state.pending = pending.superseded.map(|pending| *pending);
                    self.save(state).await?;
                    bail!("LOGIN_ALREADY_APPROVED")
                }
                state.login = None;
            }
            Target::Bootstrap => {
                let device = &data["device"];
                state.device = Some(parse_token(
                    device,
                    field(device, "deviceId")?,
                    pending.started_at,
                )?);
                state.login = None;
            }
            Target::DeviceRefresh => {
                let subject = state
                    .device
                    .as_ref()
                    .ok_or_else(|| anyhow!("AUTH_REQUIRED"))?
                    .subject
                    .clone();
                state.device = Some(parse_token(&data, subject, pending.started_at)?);
            }
            Target::ChildRefresh(org) => {
                let subject = state
                    .children
                    .get(&org)
                    .ok_or_else(|| anyhow!("AUTH_REQUIRED"))?
                    .subject
                    .clone();
                let token = parse_token(&data, subject.clone(), pending.started_at)?;
                // Preserve successful rotation material before optional Persona
                // metadata verification. Legacy children have no device attachment.
                state.children.insert(org.clone(), token);
                state.persona_state.remove(&format!("credential:{org}"));
                if data["deviceId"].is_string() {
                    if let Ok(metadata) = persona_credential_metadata(&data, &org) {
                        if metadata["runnerId"] == subject {
                            state
                                .persona_state
                                .insert(format!("credential:{org}"), metadata);
                        }
                    }
                }
            }
            Target::Enroll(org) => {
                if data["child"].get("delegationId").is_some() {
                    let metadata = json!({"deviceId":data["deviceId"],"delegationId":data["child"]["delegationId"],"organizationId":org,"runnerId":data["runner"]["id"],"scopes":data["child"]["scopes"]});
                    state.persona_state.insert(
                        format!("credential:{org}"),
                        persona_credential_metadata(&metadata, &org)?,
                    );
                }
                ensure!(
                    data.get("child").is_some(),
                    "ENROLLMENT_CREDENTIALS_UNAVAILABLE"
                );
                state.children.insert(
                    org,
                    parse_token(
                        &data["child"],
                        field(&data["runner"], "id")?,
                        pending.started_at,
                    )?,
                );
            }
        }
        state.pending = None;
        self.save(state).await
    }
}
const PERSONA_SCOPES: [&str; 4] = [
    "runner.personas.read",
    "runner.personas.chat",
    "runner.personas.memory.read",
    "runner.personas.memory.write",
];
// Management is an explicit additive grant. Keep the original four-scope set
// intact so discovery/chat clients do not acquire a new required permission.
fn persona_scope(scope: &str) -> bool {
    PERSONA_SCOPES.contains(&scope) || scope == "runner.personas.manage"
}
fn persona_credential_metadata(data: &Value, org: &str) -> Result<Value> {
    ensure!(
        data["organizationId"] == org
            && data["scopes"]
                .as_array()
                .is_some_and(|scopes| scopes.iter().all(Value::is_string)),
        "INVALID_API_RESPONSE"
    );
    for key in ["deviceId", "delegationId", "runnerId"] {
        uuid::Uuid::parse_str(&field(data, key)?).map_err(|_| anyhow!("INVALID_API_RESPONSE"))?;
    }
    Ok(
        json!({"deviceId":data["deviceId"],"delegationId":data["delegationId"],"runnerId":data["runnerId"],"organizationId":org,"scopes":data["scopes"]}),
    )
}
fn field(value: &Value, name: &str) -> Result<String> {
    value
        .get(name)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("INVALID_API_RESPONSE"))
}
fn expiry(value: &Value, started_at: u64) -> Result<u64> {
    let ttl = value["expiresInSeconds"]
        .as_u64()
        .filter(|n| *n > 0)
        .ok_or_else(|| anyhow!("INVALID_API_RESPONSE"))?;
    let dispatch_bound = started_at
        .checked_add(ttl)
        .ok_or_else(|| anyhow!("INVALID_API_RESPONSE"))?;
    match value.get("expiresAt") {
        None => Ok(dispatch_bound),
        Some(absolute) => {
            let absolute = absolute
                .as_str()
                .filter(|s| !s.is_empty() && s.len() <= 64)
                .ok_or_else(|| anyhow!("INVALID_API_RESPONSE"))?;
            let parsed = OffsetDateTime::parse(absolute, &Rfc3339)
                .map_err(|_| anyhow!("INVALID_API_RESPONSE"))?;
            let unix = u64::try_from(parsed.unix_timestamp())
                .map_err(|_| anyhow!("INVALID_API_RESPONSE"))?;
            ensure!(unix > 0, "INVALID_API_RESPONSE");
            // Server absolute expiry is authoritative. The dispatch bound is a
            // conservative cap for clock skew and old/replayed responses.
            Ok(unix.min(dispatch_bound))
        }
    }
}
fn parse_token(value: &Value, subject: String, started_at: u64) -> Result<Token> {
    Ok(Token {
        access: field(value, "accessToken")?,
        refresh: field(value, "refreshToken")?,
        subject,
        expires_at: expiry(value, started_at)?,
    })
}
fn login_projection(login: &Login) -> Value {
    json!({"status":"pending","pending":true,"flowId":login.flow_id,"authorizationUrl":login.authorization_url,"expiresAt":login.expires_at})
}
fn flow_identity(state: &ProtectedState, login: &Login) -> String {
    if login.flow_id.is_empty() {
        // Legacy protected records did not persist an explicit flow identifier.
        // Salt the stable fallback with the private key so it cannot reveal the
        // historical idempotency key or device code.
        format!(
            "legacy-{}",
            runner_state::digest(&[state.private_key.as_slice(), login.key.as_bytes()].concat())
        )
    } else {
        login.flow_id.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn current_child_identity_never_refreshes_or_writes_expired_auth() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api =
            Api::for_test_origin(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        let auth = Auth::test_enrolled(api, "organization", "runner");
        let mut state = auth.required().await.unwrap();
        state.children.get_mut("organization").unwrap().expires_at = 0;
        auth.save(&state).await.unwrap();
        let before = auth.store.load().unwrap();

        assert_eq!(
            auth.current_child_identity("organization")
                .await
                .unwrap_err()
                .to_string(),
            "AUTH_REQUIRED"
        );
        assert_eq!(auth.store.load().unwrap(), before);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), listener.accept())
                .await
                .is_err()
        );
    }
    #[tokio::test]
    async fn delayed_refresh_keeps_status_bounded_and_duplicate_rotation_serialized() {
        let (auth, store, listener) = test_auth().await;
        let mut state = ProtectedState::fresh();
        state.device = Some(Token {
            access: "lmxda_device_secret".into(),
            refresh: "device-refresh".into(),
            subject: "device".into(),
            expires_at: now() + 3600,
        });
        for org in ["slow", "unaffected"] {
            state.children.insert(
                org.into(),
                Token {
                    access: "lmxr_child_secret".into(),
                    refresh: "child-refresh".into(),
                    subject: "runner".into(),
                    expires_at: if org == "slow" { 0 } else { now() + 3600 },
                },
            );
        }
        auth.save(&state).await.unwrap();
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let server_entered = entered.clone();
        let server_release = release.clone();
        let server = tokio::spawn(async move {
            let (mut original, _) = listener.accept().await.unwrap();
            let request = read_request(&mut original).await;
            server_entered.notify_one();
            server_release.notified().await;
            drop(original);
            let (mut recovery, _) = listener.accept().await.unwrap();
            let replay = read_request(&mut recovery).await;
            assert_eq!(replay["refreshToken"], request["refreshToken"]);
            assert_eq!(replay["proof"], request["proof"]);
            assert_eq!(replay["recovery"], true);
            respond(&mut recovery,200,json!({"data":{"accessToken":"lmxr_recovered_secret","refreshToken":"recovered-refresh","expiresInSeconds":3600}})).await;
            assert!(
                tokio::time::timeout(Duration::from_millis(50), listener.accept())
                    .await
                    .is_err()
            );
        });
        let copy = auth.clone();
        let operation = tokio::spawn(async move { copy.credential("slow").await });
        entered.notified().await;
        // This bounded equivalent reproduces the original >15s lock problem:
        // readers must finish while the original transport remains withheld.
        let status = tokio::time::timeout(Duration::from_millis(300), auth.status()).await;
        let connection =
            tokio::time::timeout(Duration::from_millis(300), auth.connection(None, 0)).await;
        let duplicate = tokio::time::timeout(
            AUTH_LOCK_BUDGET + Duration::from_millis(300),
            auth.credential("unaffected"),
        )
        .await;
        let durable: ProtectedState =
            serde_json::from_slice(&store.load().unwrap().unwrap()).unwrap();
        release.notify_one();
        let recovered = operation.await.unwrap().unwrap();
        server.await.unwrap();
        assert_eq!(status.unwrap().unwrap()["code"], "AUTH_RECOVERY_PENDING");
        assert_eq!(connection.unwrap()["state"], "recovery_pending");
        assert_eq!(
            duplicate.unwrap().err().unwrap().to_string(),
            "AUTH_RECOVERY_PENDING"
        );
        assert!(durable.pending.is_some());
        assert_eq!(recovered.token, "lmxr_recovered_secret");
        assert_eq!(auth.status().await.unwrap()["code"], "AUTHENTICATED");
    }
    #[tokio::test]
    async fn refresh_response_cannot_overwrite_durable_generation_or_identity_drift() {
        for drift in ["installation", "subject", "generation", "logout"] {
            let (auth, store, listener) = test_auth().await;
            let mut state = ProtectedState::fresh();
            state.children.insert(
                "org".into(),
                Token {
                    access: "lmxr_old_secret".into(),
                    refresh: "old-refresh".into(),
                    subject: "runner".into(),
                    expires_at: 0,
                },
            );
            auth.save(&state).await.unwrap();
            let copy = auth.clone();
            let operation = tokio::spawn(async move { copy.credential("org").await });
            let (mut stream, _) = listener.accept().await.unwrap();
            read_request(&mut stream).await;
            let mut changed: ProtectedState =
                serde_json::from_slice(&store.load().unwrap().unwrap()).unwrap();
            match drift {
                "installation" => changed.installation_id = "replacement".into(),
                "subject" => {
                    changed.children.get_mut("org").unwrap().subject = "replacement".into()
                }
                "generation" => {
                    changed.children.get_mut("org").unwrap().refresh = "replacement-refresh".into()
                }
                "logout" => changed.logout_pending = true,
                _ => unreachable!(),
            }
            let bytes = serde_json::to_vec(&changed).unwrap();
            store.save(&bytes).unwrap();
            respond(&mut stream,200,json!({"data":{"accessToken":"lmxr_new_secret","refreshToken":"new-refresh","expiresInSeconds":3600}})).await;
            assert_eq!(
                operation.await.unwrap().err().unwrap().to_string(),
                "AUTH_IDENTITY_CHANGED",
                "{drift}"
            );
            assert_eq!(store.load().unwrap().unwrap(), bytes, "{drift}");
        }
    }
    #[tokio::test]
    async fn startup_observation_waits_existing_owner_and_preserves_pending_refusal() {
        let api = Api::for_test_origin("http://127.0.0.1:9").unwrap();
        let auth = Auth::test_enrolled(api, "org", "runner");
        let owner = auth.test_hold_credential_gate().await;
        let mut state = auth.required().await.unwrap();
        state.pending = Some(Pending {
            target: Target::ChildRefresh("org".into()),
            route: "v1/delegations/refresh/".into(),
            body: json!({"refreshToken":"original","proof":"identical"}),
            started_at: now(),
            recovery_used: false,
            superseded: None,
        });
        auth.save(&state).await.unwrap();
        let copy = auth.clone();
        let observation = tokio::spawn(async move { copy.startup_status().await });
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!observation.is_finished());
        assert_eq!(
            auth.status().await.unwrap()["code"],
            "AUTH_RECOVERY_PENDING"
        );
        state.pending = None;
        auth.save(&state).await.unwrap();
        drop(owner);
        assert_eq!(observation.await.unwrap().unwrap()["code"], "AUTHENTICATED");
        state.pending = Some(Pending {
            target: Target::ChildRefresh("org".into()),
            route: "v1/delegations/refresh/".into(),
            body: json!({"refreshToken":"original","proof":"identical"}),
            started_at: now(),
            recovery_used: false,
            superseded: None,
        });
        auth.save(&state).await.unwrap();
        let before = auth.store.load().unwrap();
        assert_eq!(
            auth.startup_status().await.unwrap()["code"],
            "AUTH_RECOVERY_PENDING"
        );
        assert_eq!(auth.store.load().unwrap(), before);
        assert_eq!(AUTH_STARTUP_OBSERVATION_BUDGET, Duration::from_secs(15));
        assert_eq!(AUTH_LOCK_BUDGET, Duration::from_secs(2));
    }
    #[tokio::test]
    async fn public_fixtures_use_only_memory() {
        let api = Api::for_test_origin("http://127.0.0.1:9").unwrap();
        let unauthed = Auth::test_unauthed(api.clone());
        let unauthed_status = unauthed.status().await.unwrap();
        assert_eq!(unauthed_status["code"], "AUTH_REQUIRED");
        assert_eq!(unauthed_status["loginPending"], false);
        let auth = Auth::test_enrolled(api, "organization", "runner");
        let credential = auth.credential("organization").await.unwrap();
        assert_eq!(credential.subject, "runner");
        assert_eq!(credential.private_key, [7; 32]);
        assert_eq!(
            auth.installation_id().await.unwrap(),
            "00000000-0000-4000-8000-000000000001"
        );
    }
    #[test]
    fn exact_pending_survives_restart_and_recovery_once() {
        let store = MemoryStore::default();
        let mut state = ProtectedState::fresh();
        state.pending = Some(Pending {
            target: Target::DeviceRefresh,
            route: "v2/device-authorities/refresh/".into(),
            body: json!({"refreshToken":"original","proof":"identical"}),
            started_at: 100,
            recovery_used: false,
            superseded: None,
        });
        store.save(&serde_json::to_vec(&state).unwrap()).unwrap();
        let mut restored: ProtectedState =
            serde_json::from_slice(&store.load().unwrap().unwrap()).unwrap();
        let pending = restored.pending.as_mut().unwrap();
        assert!(pending.can_recover());
        pending.started_at = 0; // An aged persistence timestamp does not prove remote expiry.
        assert!(pending.can_recover());
        assert_eq!(pending.body["proof"], "identical");
        pending.recovery_used = true;
        store.save(&serde_json::to_vec(&restored).unwrap()).unwrap();
        let restored: ProtectedState =
            serde_json::from_slice(&store.load().unwrap().unwrap()).unwrap();
        assert!(restored.pending.unwrap().can_recover());
    }
    #[test]
    fn absolute_expiry_survives_restart() {
        let token = parse_token(
            &json!({"accessToken":"a","refreshToken":"r","expiresInSeconds":120}),
            "s".into(),
            now(),
        )
        .unwrap();
        let restored: Token =
            serde_json::from_str(&serde_json::to_string(&token).unwrap()).unwrap();
        assert_eq!(token.expires_at, restored.expires_at);
        assert!(restored.usable());
        let expired = Token {
            expires_at: now() - 1,
            ..restored
        };
        assert!(!expired.usable());
    }
    #[test]
    fn delayed_and_replayed_token_responses_never_gain_receipt_lifetime() {
        let started = 1_000_000;
        let old_backend = json!({"accessToken":"a","refreshToken":"r","expiresInSeconds":900});
        let delayed = parse_token(&old_backend, "subject".into(), started).unwrap();
        assert_eq!(delayed.expires_at, started + 900);
        assert!(!delayed.usable_at(started + 1_000));

        // A recovered response uses the persisted original request start even
        // when the server processes it much later than the first attempt.
        let mut absolute = old_backend.clone();
        absolute["expiresAt"] = json!("1970-01-12T14:01:30.500000+00:00");
        assert_eq!(expiry(&absolute, started).unwrap(), started + 890);
        absolute["expiresAt"] = json!("1970-01-12T14:03:20Z");
        assert_eq!(expiry(&absolute, started).unwrap(), started + 900);
        assert!(
            !parse_token(&absolute, "subject".into(), started)
                .unwrap()
                .usable_at(started + 1_000)
        );
    }
    #[test]
    fn token_expiry_rejects_malformed_absolute_and_overflow() {
        for absolute in [
            json!(null),
            json!(900),
            json!(""),
            json!("tomorrow"),
            json!("1969-12-31T23:59:59Z"),
        ] {
            let token = json!({"accessToken":"a","refreshToken":"r","expiresInSeconds":900,"expiresAt":absolute});
            assert_eq!(
                expiry(&token, 1_000).unwrap_err().to_string(),
                "INVALID_API_RESPONSE"
            );
        }
        let token = json!({"expiresInSeconds":900});
        assert_eq!(
            expiry(&token, u64::MAX - 899).unwrap_err().to_string(),
            "INVALID_API_RESPONSE"
        );
        let token = json!({"expiresInSeconds":0});
        assert_eq!(
            expiry(&token, 1_000).unwrap_err().to_string(),
            "INVALID_API_RESPONSE"
        );
    }
    #[test]
    fn login_projection_has_no_secret() {
        let login = Login {
            key: "key".into(),
            runner_name: "runner".into(),
            flow_id: "flow-id".into(),
            code_verifier: Some("SECRET".into()),
            expires_at: 0,
            ..Login::default()
        };
        let projection = login_projection(&login);
        assert!(!projection.to_string().contains("SECRET"));
        assert_eq!(projection["flowId"], "flow-id");
    }
    #[tokio::test]
    async fn browser_launch_uses_only_the_current_sealed_flow_url() {
        let api = Api::for_test_origin("http://127.0.0.1:28080").unwrap();
        let expected = api
            .browser_authorization_uri(
                "/api/v1/runner-control/runner/v2/browser-authorities/authorize/",
                "transaction-id",
                "browser-state",
            )
            .unwrap();
        let auth = Auth::test_unauthed(api);
        let mut state = ProtectedState::fresh();
        state.login = Some(Login {
            flow_id: "current-flow".into(),
            authorization_url: Some(expected.clone()),
            transaction_id: Some("transaction-id".into()),
            browser_state: Some("browser-state".into()),
            expires_at: now() + 60,
            ..Login::default()
        });
        auth.save(&state).await.unwrap();
        let result = auth
            .open_browser_with("current-flow", move |url| async move {
                assert_eq!(url, expected);
                Ok(())
            })
            .await
            .unwrap();
        assert_eq!(result["status"], "launch_requested");
        assert_eq!(result["flowId"], "current-flow");
        assert_eq!(
            auth.open_browser_with("old-flow", |_| async { panic!("stale flow launched") })
                .await
                .unwrap_err()
                .to_string(),
            "LOGIN_FLOW_MISMATCH"
        );
        state.login.as_mut().unwrap().authorization_url = Some("https://example.test/other".into());
        auth.save(&state).await.unwrap();
        assert_eq!(
            auth.open_browser_with("current-flow", |_| async {
                panic!("unsealed URL launched")
            })
            .await
            .unwrap_err()
            .to_string(),
            "INVALID_AUTHORIZATION_URI"
        );
        state.login.as_mut().unwrap().expires_at = 0;
        auth.save(&state).await.unwrap();
        assert_eq!(
            auth.open_browser_with("current-flow", |_| async { panic!("expired URL launched") })
                .await
                .unwrap_err()
                .to_string(),
            "AUTH_EXPIRED"
        );
    }
    #[tokio::test]
    async fn connection_projection_reports_resumable_states_without_credentials() {
        let api = Api::for_test_origin("http://127.0.0.1:9").unwrap();
        let auth = Auth::test_unauthed(api);
        assert_eq!(auth.connection(None, 3).await["state"], "signed_out");

        let mut state = ProtectedState::fresh();
        state.login = Some(Login {
            key: "idempotency-key".into(),
            runner_name: "runner".into(),
            flow_id: "opaque-flow".into(),
            authorization_url: Some("https://example.test/authorize".into()),
            code_verifier: Some("SECRET".into()),
            expires_at: now() + 60,
            ..Login::default()
        });
        auth.save(&state).await.unwrap();
        let pending = auth.connection(None, 1).await;
        assert_eq!(pending["state"], "recovery_pending");
        assert_eq!(pending["login"]["flowId"], "opaque-flow");
        assert!(pending["login"].get("userCode").is_none());
        assert!(!pending.to_string().contains("SECRET"));
        assert!(!pending.to_string().contains("idempotency-key"));

        state.login.as_mut().unwrap().expires_at = 0;
        auth.save(&state).await.unwrap();
        assert_eq!(
            auth.connection(None, 0).await["state"],
            "verification_expired"
        );

        state.login = None;
        state.device = Some(Token {
            access: "device-secret".into(),
            refresh: "device-refresh".into(),
            subject: "device".into(),
            expires_at: now() + 3600,
        });
        state.children.insert(
            "org".into(),
            Token {
                access: "child-secret".into(),
                refresh: "child-refresh".into(),
                subject: "runner".into(),
                expires_at: now() + 3600,
            },
        );
        auth.save(&state).await.unwrap();
        let required = auth.connection(None, 0).await;
        assert_eq!(required["state"], "authenticated");
        assert_eq!(required["organization"]["status"], "organization_required");
        let connected = auth.connection(Some("org".into()), 0).await;
        assert_eq!(connected["organization"]["status"], "connected");
        assert_eq!(connected["organizations"][0]["id"], "org");
        assert!(!connected.to_string().contains("child-secret"));

        state.pending = Some(Pending {
            target: Target::DeviceRefresh,
            route: "v2/device-authorities/refresh/".into(),
            body: json!({"refreshToken":"secret"}),
            started_at: now(),
            recovery_used: false,
            superseded: None,
        });
        auth.save(&state).await.unwrap();
        assert_eq!(auth.connection(None, 0).await["state"], "recovery_pending");
        state.pending = None;
        state.logout_pending = true;
        auth.save(&state).await.unwrap();
        assert_eq!(auth.connection(None, 0).await["state"], "logout_pending");
    }
    #[tokio::test]
    async fn connection_projection_handles_an_unavailable_credential_store() {
        struct Unavailable;
        impl Store for Unavailable {
            fn load(&self) -> Result<Option<Vec<u8>>> {
                bail!("STORE_UNAVAILABLE")
            }
            fn save(&self, _: &[u8]) -> Result<()> {
                bail!("STORE_UNAVAILABLE")
            }
        }
        let auth = Auth {
            api: Api::for_test_origin("http://127.0.0.1:9").unwrap(),
            store: Arc::new(Unavailable),
            operation_lock: Arc::new(Mutex::new(())),
            store_lock: Arc::new(Mutex::new(())),
            store_owner: Arc::new(std::sync::Mutex::new(None)),
            listeners: Arc::new(Mutex::new(BTreeMap::new())),
        };
        let projection = auth.connection(None, 0).await;
        assert_eq!(projection["state"], "credential_store_unavailable");
        assert_eq!(projection["actions"], json!([]));
    }
    #[tokio::test]
    async fn organization_cache_is_local_and_survives_a_list_failure() {
        let (auth, _, listener) = test_auth().await;
        let mut state = ProtectedState::fresh();
        state.device = Some(Token {
            access: "lmxda_device-access".into(),
            refresh: "device-refresh".into(),
            subject: "device".into(),
            expires_at: now() + 3600,
        });
        state.children.insert(
            "org-a".into(),
            Token {
                access: "child-access".into(),
                refresh: "child-refresh".into(),
                subject: "runner".into(),
                expires_at: now() + 3600,
            },
        );
        auth.save(&state).await.unwrap();
        let before = auth.status().await.unwrap();
        assert_eq!(before["code"], "AUTHENTICATED", "{before}");
        assert!(auth.required().await.unwrap().device.unwrap().usable());
        let server = tokio::spawn(async move {
            let (mut first, _) = listener.accept().await.unwrap();
            respond(
                &mut first,
                200,
                json!({"data":{"organizations":[
                    {"id":"org-a","name":"Alpha","slug":"alpha","enrolled":true,"runner":null},
                    {"id":"org-b","name":"Beta","slug":"beta","enrolled":false,"runner":null}
                ]}}),
            )
            .await;
            let (mut second, _) = listener.accept().await.unwrap();
            respond(
                &mut second,
                503,
                json!({"error":{"code":"BACKEND_UNAVAILABLE"}}),
            )
            .await;
        });
        assert_eq!(
            auth.organizations().await.unwrap()["organizations"][0]["name"],
            "Alpha"
        );
        let cached = auth.connection(Some("org-a".into()), 0).await;
        assert_eq!(cached["organization"]["selected"]["name"], "Alpha");
        assert_eq!(cached["organizations"].as_array().unwrap().len(), 2);
        assert_eq!(cached["organizations"][1]["name"], "Beta");
        assert!(auth.organizations().await.is_err());
        let after_failure = auth.connection(Some("org-a".into()), 0).await;
        assert_eq!(after_failure["state"], "authenticated");
        assert_eq!(after_failure["organization"]["selected"]["name"], "Alpha");
        server.await.unwrap();
    }
    #[test]
    fn legacy_protected_state_loads_with_a_stable_opaque_flow_and_empty_profile_cache() {
        let mut state = ProtectedState::fresh();
        state.login = Some(Login {
            key: "historic-key".into(),
            runner_name: "runner".into(),
            flow_id: "new-flow".into(),
            expires_at: now() + 60,
            ..Login::default()
        });
        let mut legacy = serde_json::to_value(&state).unwrap();
        legacy
            .as_object_mut()
            .unwrap()
            .remove("organization_profiles");
        legacy["login"].as_object_mut().unwrap().remove("flow_id");
        let restored: ProtectedState = serde_json::from_value(legacy).unwrap();
        assert!(restored.organization_profiles.is_empty());
        let identity = flow_identity(&restored, restored.login.as_ref().unwrap());
        assert!(identity.starts_with("legacy-"));
        assert_ne!(identity, "historic-key");
    }
    async fn read_request(stream: &mut tokio::net::TcpStream) -> Value {
        use tokio::io::AsyncReadExt;
        let mut bytes = Vec::new();
        let mut chunk = [0u8; 2048];
        loop {
            let count = stream.read(&mut chunk).await.unwrap();
            assert!(count > 0);
            bytes.extend_from_slice(&chunk[..count]);
            if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                let headers = String::from_utf8_lossy(&bytes[..end]);
                let length = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().unwrap())
                    })
                    .unwrap_or(0);
                if bytes.len() >= end + 4 + length {
                    if length == 0 {
                        return Value::Null;
                    }
                    return serde_json::from_slice(&bytes[end + 4..end + 4 + length]).unwrap();
                }
            }
        }
    }
    async fn respond(stream: &mut tokio::net::TcpStream, status: u16, body: Value) {
        use tokio::io::AsyncWriteExt;
        let body = body.to_string();
        let response = format!(
            "HTTP/1.1 {status} Result\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes()).await.unwrap();
    }
    async fn test_auth() -> (Auth, Arc<MemoryStore>, tokio::net::TcpListener) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api = Api::with_origin(
            url::Url::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap(),
        )
        .unwrap();
        let store = Arc::new(MemoryStore::default());
        let auth = Auth {
            api,
            store: store.clone(),
            operation_lock: Arc::new(Mutex::new(())),
            store_lock: Arc::new(Mutex::new(())),
            store_owner: Arc::new(std::sync::Mutex::new(None)),
            listeners: Arc::new(Mutex::new(BTreeMap::new())),
        };
        (auth, store, listener)
    }
    #[tokio::test]
    async fn browser_callback_completes_exchange_and_existing_bootstrap_chain() {
        let (auth, _, server) = test_auth().await;
        let server_task = tokio::spawn(async move {
            for (index, expected_path) in [
                "/v2/browser-authorities/start/",
                "/v2/browser-authorities/exchange/",
                "/v2/device-authorities/bootstrap/",
            ]
            .iter()
            .enumerate()
            {
                let (mut socket, _) = server.accept().await.unwrap();
                let request = read_request(&mut socket).await;
                if index == 0 {
                    assert_eq!(request["clientId"], "loomex-native/v1");
                    assert!(
                        request["redirectUri"]
                            .as_str()
                            .unwrap()
                            .starts_with("http://127.0.0.1:")
                    );
                }
                if index == 1 {
                    assert_eq!(
                        request["code"],
                        "callback-code-with-sufficient-entropy-0001"
                    );
                    assert!(request["codeVerifier"].as_str().unwrap().len() >= 43);
                }
                let payload = match index {
                    0 => {
                        json!({"data":{"transactionId":"00000000-0000-4000-8000-000000000004","authorizationPath":"/api/v1/runner-control/runner/v2/browser-authorities/authorize/","expiresAt":now()+600}})
                    }
                    1 => json!({"data":{"bootstrapGrant":"one-bootstrap-grant"}}),
                    _ => {
                        json!({"data":{"device":{"deviceId":"00000000-0000-4000-8000-000000000005","accessToken":"lmxda_access","refreshToken":"lmxdr_refresh","expiresInSeconds":900}}})
                    }
                };
                let _ = expected_path;
                respond(&mut socket, 200, payload).await;
            }
        });
        let started = auth
            .login("Test runner", "00000000-0000-4000-8000-000000000001")
            .await
            .unwrap();
        assert_eq!(started["status"], "pending");
        assert!(started.get("userCode").is_none());
        let state = auth.required().await.unwrap();
        let login = state.login.unwrap();
        let uri = login.redirect_uri.unwrap();
        let address = uri
            .trim_start_matches("http://")
            .trim_end_matches("/oauth/callback");
        let mut invalid = tokio::net::TcpStream::connect(address).await.unwrap();
        invalid
            .write_all(format!("GET /oauth/callback?state=wrong&code=callback-code-with-sufficient-entropy-0001 HTTP/1.1\r\nHost: {address}\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut invalid_response = [0u8; 512];
        let invalid_size = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            invalid.read(&mut invalid_response),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(
            std::str::from_utf8(&invalid_response[..invalid_size])
                .unwrap()
                .starts_with("HTTP/1.1 400")
        );
        assert_eq!(auth.connection(None, 0).await["state"], "browser_pending");
        let mut callback = tokio::net::TcpStream::connect(address).await.unwrap();
        let request = format!(
            "GET /oauth/callback?state={}&code=callback-code-with-sufficient-entropy-0001 HTTP/1.1\r\nHost: {address}\r\n\r\n",
            login.browser_state.unwrap()
        );
        callback.write_all(request.as_bytes()).await.unwrap();
        let mut response = [0u8; 512];
        let size = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            callback.read(&mut response),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(
            std::str::from_utf8(&response[..size])
                .unwrap()
                .starts_with("HTTP/1.1 200")
        );
        server_task.await.unwrap();
        assert_eq!(auth.connection(None, 0).await["state"], "authenticated");
    }

    #[test]
    fn browser_callback_pages_share_the_generated_design_and_restrict_inline_style() {
        let style_hash = STANDARD.encode(Sha256::digest(BROWSER_AUTH_CSS.as_bytes()));
        for (outcome, status, title) in [
            (BrowserCallbackOutcome::SignedIn, "200 OK", "Signed in"),
            (
                BrowserCallbackOutcome::Declined,
                "200 OK",
                "Sign-in declined",
            ),
            (
                BrowserCallbackOutcome::RecoveryRequired,
                "202 Accepted",
                "Sign-in needs attention",
            ),
            (
                BrowserCallbackOutcome::Invalid,
                "400 Bad Request",
                "Sign-in unavailable",
            ),
        ] {
            let response = browser_callback_response(outcome);
            assert!(response.starts_with(&format!("HTTP/1.1 {status}\r\n")));
            assert!(response.contains(&format!("style-src 'sha256-{style_hash}'")));
            assert!(response.contains(&format!("<h1 class=\"auth-title\">{title}</h1>")));
            assert!(response.contains(BROWSER_AUTH_CSS));
            assert!(response.contains("Cache-Control: no-store"));
            assert!(!response.contains("<script"));
        }
        assert!(
            browser_callback_response(BrowserCallbackOutcome::SignedIn)
                .contains("Return to the Loomex connection card to finish setup.")
        );
    }
    #[tokio::test]
    async fn concurrent_refresh_is_singleflight_and_recovery_is_durable() {
        let (auth, store, listener) = test_auth().await;
        let mut state = ProtectedState::fresh();
        state.children.insert(
            "org".into(),
            Token {
                access: "lmxr_old_secret".into(),
                refresh: "original-refresh".into(),
                subject: "runner".into(),
                expires_at: 0,
            },
        );
        auth.save(&state).await.unwrap();
        let server_store = store.clone();
        let server = tokio::spawn(async move {
            let (mut first, _) = listener.accept().await.unwrap();
            let original = read_request(&mut first).await;
            let durable: ProtectedState =
                serde_json::from_slice(&server_store.load().unwrap().unwrap()).unwrap();
            let pending = durable.pending.unwrap();
            assert_eq!(pending.body, original);
            assert!(!pending.recovery_used);
            drop(first); // Successful remote rotation whose response never reached the client.
            let (mut second, _) = listener.accept().await.unwrap();
            let recovery = read_request(&mut second).await;
            assert_eq!(recovery["refreshToken"], original["refreshToken"]);
            assert_eq!(recovery["proof"], original["proof"]);
            assert_eq!(recovery["recovery"], true);
            let durable: ProtectedState =
                serde_json::from_slice(&server_store.load().unwrap().unwrap()).unwrap();
            assert!(durable.pending.unwrap().recovery_used);
            respond(&mut second,200,json!({"data":{"accessToken":"lmxr_new_secret","refreshToken":"replacement","expiresInSeconds":3600}})).await;
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(100), listener.accept())
                    .await
                    .is_err()
            );
        });
        let (first, second) = tokio::join!(auth.credential("org"), auth.credential("org"));
        assert_eq!(first.unwrap().token, "lmxr_new_secret");
        assert_eq!(second.unwrap().token, "lmxr_new_secret");
        server.await.unwrap();
        let durable: ProtectedState =
            serde_json::from_slice(&store.load().unwrap().unwrap()).unwrap();
        assert!(durable.pending.is_none());
        assert_eq!(durable.children["org"].refresh, "replacement");
        let status = auth.status().await.unwrap().to_string();
        assert!(!status.contains("replacement") && !status.contains("lmxr_"));
    }
    #[tokio::test]
    async fn recovered_expired_child_commits_refresh_material_then_refreshes_before_signing() {
        let (auth, store, listener) = test_auth().await;
        let mut state = ProtectedState::fresh();
        state.children.insert(
            "org".into(),
            Token {
                access: "old-access".into(),
                refresh: "old-refresh".into(),
                subject: "runner".into(),
                expires_at: 0,
            },
        );
        let old_start = now().saturating_sub(1_200);
        state.pending = Some(Pending {
            target: Target::ChildRefresh("org".into()),
            route: "v1/delegations/refresh/".into(),
            body: json!({"refreshToken":"old-refresh","proof":"original-proof"}),
            started_at: old_start,
            recovery_used: false,
            superseded: None,
        });
        auth.save(&state).await.unwrap();
        let server = tokio::spawn(async move {
            let (mut recovered, _) = listener.accept().await.unwrap();
            let request = read_request(&mut recovered).await;
            assert_eq!(request["refreshToken"], "old-refresh");
            assert_eq!(request["proof"], "original-proof");
            assert_eq!(request["recovery"], true);
            respond(
                &mut recovered,
                200,
                json!({"data":{
                    "accessToken":"expired-recovered-access",
                    "refreshToken":"recovered-refresh",
                    "expiresInSeconds":900
                }}),
            )
            .await;

            let (mut refreshed, _) = listener.accept().await.unwrap();
            let request = read_request(&mut refreshed).await;
            assert_eq!(request["refreshToken"], "recovered-refresh");
            assert!(request.get("recovery").is_none());
            assert_ne!(request["proof"], "original-proof");
            respond(
                &mut refreshed,
                200,
                json!({"data":{
                    "accessToken":"fresh-access",
                    "refreshToken":"fresh-refresh",
                    "expiresInSeconds":900
                }}),
            )
            .await;
        });
        let credential = auth.credential("org").await.unwrap();
        assert_eq!(credential.token, "fresh-access");
        server.await.unwrap();
        let durable: ProtectedState =
            serde_json::from_slice(&store.load().unwrap().unwrap()).unwrap();
        assert!(durable.pending.is_none());
        assert_eq!(durable.children["org"].refresh, "fresh-refresh");
        assert!(durable.children["org"].usable());
    }
    #[tokio::test]
    async fn expired_browser_exchange_can_be_canceled_without_replaying_exchange() {
        let (auth, store, listener) = test_auth().await;
        let mut state = ProtectedState::fresh();
        let identity = state.installation_id.clone();
        state.login = Some(Login {
            flow_id: "expired-flow".into(),
            transaction_id: Some(uuid::Uuid::new_v4().to_string()),
            browser_state: Some("s".repeat(48)),
            expires_at: 0,
            ..Login::default()
        });
        state.pending = Some(Pending {
            target: Target::BrowserExchange,
            route: "v2/browser-authorities/exchange/".into(),
            body: json!({"proof":"retained-exchange-proof"}),
            started_at: now(),
            recovery_used: true,
            superseded: None,
        });
        auth.save(&state).await.unwrap();
        let projection = auth.connection(None, 0).await;
        assert_eq!(projection["login"]["flowId"], "expired-flow");
        assert!(
            projection["actions"]
                .as_array()
                .unwrap()
                .contains(&json!("auth.cancel"))
        );
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_request(&mut stream).await;
            assert_eq!(request["revokeApproved"], true);
            assert!(request.get("superseded").is_none());
            assert!(!request.to_string().contains("retained-exchange-proof"));
            respond(&mut stream, 200, json!({"data":{"canceled":true}})).await;
        });
        assert_eq!(
            auth.cancel_login("expired-flow").await.unwrap()["canceled"],
            true
        );
        server.await.unwrap();
        let saved: ProtectedState =
            serde_json::from_slice(&store.load().unwrap().unwrap()).unwrap();
        assert_eq!(saved.installation_id, identity);
        assert!(saved.pending.is_none() && saved.login.is_none() && saved.device.is_none());
    }

    #[tokio::test]
    async fn browser_cancel_ambiguity_retains_superseded_proof_until_exact_recovery() {
        let (auth, store, listener) = test_auth().await;
        let mut state = ProtectedState::fresh();
        state.login = Some(Login {
            flow_id: "recovery-flow".into(),
            transaction_id: Some(uuid::Uuid::new_v4().to_string()),
            browser_state: Some("s".repeat(48)),
            expires_at: 0,
            ..Login::default()
        });
        state.pending = Some(Pending {
            target: Target::Bootstrap,
            route: "v2/device-authorities/bootstrap/".into(),
            body: json!({"bootstrapGrant":"original-grant","proof":"original-proof"}),
            started_at: now(),
            recovery_used: true,
            superseded: None,
        });
        auth.save(&state).await.unwrap();
        let server_store = store.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let first = read_request(&mut stream).await;
            let saved: ProtectedState =
                serde_json::from_slice(&server_store.load().unwrap().unwrap()).unwrap();
            let pending = saved.pending.unwrap();
            assert!(matches!(pending.target, Target::BrowserCancel));
            assert_eq!(pending.superseded.unwrap().body["proof"], "original-proof");
            respond(
                &mut stream,
                503,
                json!({"error":{"code":"NETWORK_UNAVAILABLE","message":"Unavailable"}}),
            )
            .await;
            let (mut stream, _) = listener.accept().await.unwrap();
            let second = read_request(&mut stream).await;
            assert_eq!(second["proof"], first["proof"]);
            assert_eq!(second["transactionId"], first["transactionId"]);
            assert_eq!(second["revokeApproved"], true);
            assert_eq!(second["recovery"], true);
            respond(&mut stream, 200, json!({"data":{"canceled":true}})).await;
        });
        assert!(auth.cancel_login("recovery-flow").await.is_err());
        let saved: ProtectedState =
            serde_json::from_slice(&store.load().unwrap().unwrap()).unwrap();
        assert!(saved.pending.unwrap().superseded.is_some());
        // Re-read the persisted intent rather than create a replacement proof.
        assert_eq!(
            auth.cancel_login("recovery-flow").await.unwrap()["canceled"],
            true
        );
        server.await.unwrap();
        assert_eq!(auth.connection(None, 0).await["state"], "signed_out");
    }

    #[tokio::test]
    async fn unsupported_browser_revocation_preserves_original_operation() {
        let (auth, store, listener) = test_auth().await;
        let mut state = ProtectedState::fresh();
        state.login = Some(Login {
            flow_id: "old-backend".into(),
            transaction_id: Some(uuid::Uuid::new_v4().to_string()),
            browser_state: Some("s".repeat(48)),
            expires_at: 0,
            ..Login::default()
        });
        state.pending = Some(Pending {
            target: Target::Bootstrap,
            route: "v2/device-authorities/bootstrap/".into(),
            body: json!({"proof":"original-proof"}),
            started_at: now(),
            recovery_used: false,
            superseded: None,
        });
        auth.save(&state).await.unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            read_request(&mut stream).await;
            respond(&mut stream, 200, json!({"data":{"canceled":false}})).await;
        });
        assert_eq!(
            auth.cancel_login("old-backend")
                .await
                .unwrap_err()
                .to_string(),
            "LOGIN_ALREADY_APPROVED"
        );
        server.await.unwrap();
        let saved: ProtectedState =
            serde_json::from_slice(&store.load().unwrap().unwrap()).unwrap();
        assert_eq!(saved.pending.unwrap().body["proof"], "original-proof");
        assert!(saved.login.is_some());
    }

    #[tokio::test]
    async fn retrying_expired_start_keeps_original_request_identity() {
        let (auth, store, listener) = test_auth().await;
        let mut state = ProtectedState::fresh();
        let key = uuid::Uuid::new_v4().to_string();
        state.login = Some(Login {
            key: key.clone(),
            runner_name: "Runner".into(),
            flow_id: "original-flow".into(),
            browser_state: Some("s".repeat(48)),
            code_verifier: Some("v".repeat(43)),
            redirect_uri: Some("http://127.0.0.1:39217/oauth/callback".into()),
            expires_at: now() - 60,
            ..Login::default()
        });
        auth.save(&state).await.unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_request(&mut stream).await;
            assert_eq!(request["state"], "s".repeat(48));
            assert_eq!(
                request["redirectUri"],
                "http://127.0.0.1:39217/oauth/callback"
            );
            respond(&mut stream,201,json!({"data":{"transactionId":uuid::Uuid::new_v4().to_string(),
                "expiresAt":0,"authorizationPath":"/api/v1/runner-control/runner/v2/browser-authorities/authorize/"}})).await;
        });
        auth.login("Runner", &key).await.unwrap();
        server.await.unwrap();
        let saved: ProtectedState =
            serde_json::from_slice(&store.load().unwrap().unwrap()).unwrap();
        assert_eq!(saved.login.unwrap().flow_id, "original-flow");
        assert_eq!(
            auth.connection(None, 0).await["actions"],
            json!(["auth.cancel"])
        );
    }

    #[tokio::test]
    async fn retrying_decided_start_does_not_reopen_approval_or_browser() {
        let (auth, store, listener) = test_auth().await;
        let mut state = ProtectedState::fresh();
        let key = uuid::Uuid::new_v4().to_string();
        state.login = Some(Login {
            key: key.clone(),
            runner_name: "Runner".into(),
            flow_id: "original-flow".into(),
            browser_state: Some("s".repeat(48)),
            code_verifier: Some("v".repeat(43)),
            redirect_uri: Some("http://127.0.0.1:39217/oauth/callback".into()),
            expires_at: now() - 60,
            ..Login::default()
        });
        auth.save(&state).await.unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_request(&mut stream).await;
            assert_eq!(request["state"], "s".repeat(48));
            assert_eq!(
                request["redirectUri"],
                "http://127.0.0.1:39217/oauth/callback"
            );
            respond(&mut stream,201,json!({"data":{"transactionId":uuid::Uuid::new_v4().to_string(),
                "expiresAt":now()+600,"status":"approved","authorizationPath":"/api/v1/runner-control/runner/v2/browser-authorities/authorize/"}})).await;
        });
        auth.login("Runner", &key).await.unwrap();
        server.await.unwrap();
        let saved: ProtectedState =
            serde_json::from_slice(&store.load().unwrap().unwrap()).unwrap();
        assert_eq!(saved.login.unwrap().flow_id, "original-flow");
        assert_eq!(
            auth.connection(None, 0).await["actions"],
            json!(["auth.cancel"])
        );
    }

    #[tokio::test]
    async fn repeated_expired_child_refresh_fails_closed_with_latest_material_saved() {
        let (auth, store, listener) = test_auth().await;
        let mut state = ProtectedState::fresh();
        state.children.insert(
            "org".into(),
            Token {
                access: "old-access".into(),
                refresh: "old-refresh".into(),
                subject: "runner".into(),
                expires_at: 0,
            },
        );
        auth.save(&state).await.unwrap();
        let server = tokio::spawn(async move {
            for (expected, next) in [("old-refresh", "refresh-1"), ("refresh-1", "refresh-2")] {
                let (mut stream, _) = listener.accept().await.unwrap();
                let request = read_request(&mut stream).await;
                assert_eq!(request["refreshToken"], expected);
                respond(
                    &mut stream,
                    200,
                    json!({"data":{
                        "accessToken":"expired-access", "refreshToken":next,
                        "expiresInSeconds":1
                    }}),
                )
                .await;
            }
        });
        assert_eq!(
            auth.credential("org").await.err().unwrap().to_string(),
            "AUTH_EXPIRED"
        );
        server.await.unwrap();
        let durable: ProtectedState =
            serde_json::from_slice(&store.load().unwrap().unwrap()).unwrap();
        assert!(durable.pending.is_none());
        assert_eq!(durable.children["org"].refresh, "refresh-2");
        assert!(!durable.children["org"].usable());
    }
    #[tokio::test]
    async fn expired_device_refresh_never_sends_a_bearer_to_organizations() {
        let (auth, store, listener) = test_auth().await;
        let mut state = ProtectedState::fresh();
        state.device = Some(Token {
            access: "old-device-access".into(),
            refresh: "old-device-refresh".into(),
            subject: "device".into(),
            expires_at: 0,
        });
        auth.save(&state).await.unwrap();
        let server = tokio::spawn(async move {
            for (expected, next) in [
                ("old-device-refresh", "device-refresh-1"),
                ("device-refresh-1", "device-refresh-2"),
            ] {
                let (mut stream, _) = listener.accept().await.unwrap();
                let request = read_request(&mut stream).await;
                assert_eq!(request["refreshToken"], expected);
                respond(
                    &mut stream,
                    200,
                    json!({"data":{
                        "accessToken":"expired-device-access", "refreshToken":next,
                        "expiresInSeconds":1
                    }}),
                )
                .await;
            }
            // A GET would carry an expired device Bearer. Bounded refresh
            // failure must return before one is transmitted.
            assert_eq!(
                listener.into_std().unwrap().accept().unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
        });
        assert_eq!(
            auth.organizations().await.err().unwrap().to_string(),
            "AUTH_EXPIRED"
        );
        server.await.unwrap();
        let durable: ProtectedState =
            serde_json::from_slice(&store.load().unwrap().unwrap()).unwrap();
        assert_eq!(durable.device.unwrap().refresh, "device-refresh-2");
    }
    #[tokio::test]
    async fn recovered_bootstrap_uses_original_request_start_for_device_expiry() {
        let (auth, store, listener) = test_auth().await;
        let mut state = ProtectedState::fresh();
        let old_start = now().saturating_sub(1_200);
        state.pending = Some(Pending {
            target: Target::Bootstrap,
            route: "v2/device-authorities/bootstrap/".into(),
            body: json!({"bootstrapGrant":"original-grant","proof":"original-proof"}),
            started_at: old_start,
            recovery_used: false,
            superseded: None,
        });
        auth.save(&state).await.unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_request(&mut stream).await;
            assert_eq!(request["recovery"], true);
            respond(
                &mut stream,
                200,
                json!({"data":{"device":{
                    "deviceId":"device", "accessToken":"expired-access",
                    "refreshToken":"usable-refresh", "expiresInSeconds":900
                }}}),
            )
            .await;
        });
        assert_eq!(auth.reconcile().await.unwrap()["reconciled"], true);
        server.await.unwrap();
        let durable: ProtectedState =
            serde_json::from_slice(&store.load().unwrap().unwrap()).unwrap();
        assert!(durable.pending.is_none());
        assert_eq!(durable.device.as_ref().unwrap().expires_at, old_start + 900);
        assert!(!durable.device.unwrap().usable());
    }
    #[tokio::test]
    async fn recovered_enrollment_uses_original_request_start_for_child_expiry() {
        let (auth, store, listener) = test_auth().await;
        let mut state = ProtectedState::fresh();
        state.device = Some(Token {
            access: "lmxda_deviceprefix_deviceaccess".into(),
            refresh: "device-refresh".into(),
            subject: "device".into(),
            expires_at: now() + 900,
        });
        let old_start = now().saturating_sub(1_200);
        state.pending = Some(Pending {
            target: Target::Enroll("org".into()),
            route: "v2/organizations/org/enroll/".into(),
            body: json!({"idempotencyKey":"original-key"}),
            started_at: old_start,
            recovery_used: false,
            superseded: None,
        });
        auth.save(&state).await.unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_request(&mut stream).await;
            assert_eq!(request["recovery"], true);
            respond(
                &mut stream,
                200,
                json!({"data":{
                    "runner":{"id":"runner"},
                    "child":{"accessToken":"expired-child", "refreshToken":"usable-refresh",
                        "expiresInSeconds":900}
                }}),
            )
            .await;
        });
        assert_eq!(auth.reconcile().await.unwrap()["reconciled"], true);
        server.await.unwrap();
        let durable: ProtectedState =
            serde_json::from_slice(&store.load().unwrap().unwrap()).unwrap();
        assert!(durable.pending.is_none());
        assert_eq!(durable.children["org"].expires_at, old_start + 900);
        assert!(!durable.children["org"].usable());
    }
    #[tokio::test]
    async fn enrollment_with_expired_device_never_sends_bearer_or_discards_ambiguous_recovery() {
        let (auth, store, listener) = test_auth().await;
        let mut state = ProtectedState::fresh();
        state.device = Some(Token {
            access: "expired-device-access".into(),
            refresh: "device-refresh".into(),
            subject: "device".into(),
            expires_at: 0,
        });
        auth.save(&state).await.unwrap();
        // Model the device crossing its expiry reserve during the protected
        // store write, after select's initial ensure_device check.
        let result = auth
            .begin(
                &mut state,
                Target::Enroll("org".into()),
                "v2/organizations/org/enroll/".into(),
                json!({"idempotencyKey":"original-key"}),
            )
            .await;
        assert_eq!(result.err().unwrap().to_string(), "AUTH_EXPIRED");
        assert!(state.pending.is_none());
        let durable: ProtectedState =
            serde_json::from_slice(&store.load().unwrap().unwrap()).unwrap();
        assert!(durable.pending.is_none());

        state.pending = Some(Pending {
            target: Target::Enroll("org".into()),
            route: "v2/organizations/org/enroll/".into(),
            body: json!({"idempotencyKey":"original-key"}),
            started_at: now().saturating_sub(1_200),
            recovery_used: false,
            superseded: None,
        });
        auth.save(&state).await.unwrap();
        assert_eq!(
            auth.reconcile().await.err().unwrap().to_string(),
            "AUTH_EXPIRED"
        );
        let durable: ProtectedState =
            serde_json::from_slice(&store.load().unwrap().unwrap()).unwrap();
        assert!(durable.pending.is_some());
        assert_eq!(
            listener.into_std().unwrap().accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
    #[tokio::test]
    async fn offline_bootstrap_cleanup_requires_recovered_revocable_authority() {
        for outcome in ["recovered", "denied", "exhausted"] {
            let (auth, store, listener) = test_auth().await;
            let mut state = ProtectedState::fresh();
            let original_key = state.private_key;
            state.pending = Some(Pending {
                target: Target::Bootstrap,
                route: "v2/device-authorities/bootstrap/".into(),
                body: json!({"bootstrapGrant":"original-grant","proof":"original-proof"}),
                started_at: now(),
                recovery_used: outcome == "exhausted",
                superseded: None,
            });
            auth.save(&state).await.unwrap();
            let server_store = store.clone();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let request = read_request(&mut stream).await;
                assert_eq!(request["recovery"], true);
                assert_eq!(request["bootstrapGrant"], "original-grant");
                let durable: ProtectedState =
                    serde_json::from_slice(&server_store.load().unwrap().unwrap()).unwrap();
                assert!(durable.logout_pending);
                if outcome == "recovered" {
                    respond(&mut stream,200,json!({"data":{"device":{"deviceId":"00000000-0000-4000-8000-000000000002","accessToken":"lmxda_recovered_secret","refreshToken":"refresh","expiresInSeconds":3600}}})).await;
                    let (mut stream, _) = listener.accept().await.unwrap();
                    assert_eq!(read_request(&mut stream).await, json!({}));
                    respond(&mut stream, 200, json!({"data":{"revoked":true}})).await;
                } else {
                    respond(
                        &mut stream,
                        409,
                        json!({"error":{"code":"RECOVERY_EXHAUSTED"}}),
                    )
                    .await;
                }
                assert!(
                    tokio::time::timeout(std::time::Duration::from_millis(50), listener.accept())
                        .await
                        .is_err()
                );
            });
            let result = auth.offline_logout().await;
            if outcome == "recovered" {
                assert_eq!(result.unwrap()["revoked"], true);
                assert!(store.load().unwrap().is_none());
            } else {
                assert_eq!(
                    result.unwrap_err().to_string(),
                    "AUTH_RECONCILIATION_REQUIRED"
                );
                let durable: ProtectedState =
                    serde_json::from_slice(&store.load().unwrap().unwrap()).unwrap();
                assert!(durable.logout_pending && durable.pending.as_ref().unwrap().recovery_used);
                assert_eq!(durable.private_key, original_key);
                assert_eq!(durable.pending.unwrap().body["proof"], "original-proof");
            }
            server.await.unwrap();
        }
    }
    #[tokio::test]
    async fn offline_cleanup_preserves_recovery_until_revocation_and_retries_delete_failure() {
        use std::sync::atomic::{AtomicBool, Ordering};
        struct DeleteOnce {
            memory: Arc<MemoryStore>,
            fail: AtomicBool,
        }
        impl Store for DeleteOnce {
            fn load(&self) -> Result<Option<Vec<u8>>> {
                self.memory.load()
            }
            fn save(&self, data: &[u8]) -> Result<()> {
                self.memory.save(data)
            }
            fn delete(&self) -> Result<()> {
                let durable: ProtectedState =
                    serde_json::from_slice(&self.memory.load()?.unwrap())?;
                ensure!(
                    durable.device.is_none() && !durable.logout_pending,
                    "deletion before revocation"
                );
                if self.fail.swap(false, Ordering::SeqCst) {
                    bail!("STORE_UNAVAILABLE");
                }
                self.memory.delete()
            }
        }
        let (mut auth, memory, listener) = test_auth().await;
        auth.store = Arc::new(DeleteOnce {
            memory: memory.clone(),
            fail: AtomicBool::new(true),
        });
        let mut state = ProtectedState::fresh();
        state.device = Some(Token {
            access: "lmxda_prefix_secret".into(),
            refresh: "refresh".into(),
            subject: "device".into(),
            expires_at: 0,
        });
        auth.save(&state).await.unwrap();
        let server = tokio::spawn(async move {
            for status in [503, 200] {
                let (mut stream, _) = listener.accept().await.unwrap();
                read_request(&mut stream).await;
                respond(
                    &mut stream,
                    status,
                    if status == 200 {
                        json!({"data":{"revoked":true}})
                    } else {
                        json!({"error":{"code":"BACKEND_UNAVAILABLE"}})
                    },
                )
                .await;
            }
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(100), listener.accept())
                    .await
                    .is_err()
            );
        });
        assert!(auth.offline_logout().await.is_err());
        let durable: ProtectedState =
            serde_json::from_slice(&memory.load().unwrap().unwrap()).unwrap();
        assert!(durable.logout_pending && durable.device.is_some());
        assert_eq!(
            auth.offline_logout().await.unwrap_err().to_string(),
            "STORE_UNAVAILABLE"
        );
        let durable: ProtectedState =
            serde_json::from_slice(&memory.load().unwrap().unwrap()).unwrap();
        assert!(!durable.logout_pending && durable.device.is_none());
        assert_eq!(auth.offline_logout().await.unwrap()["revoked"], true);
        assert!(memory.load().unwrap().is_none());
        server.await.unwrap();
    }
    #[tokio::test(flavor = "current_thread")]
    async fn canceled_offline_deletion_cannot_erase_a_later_installation_write() {
        struct GatedDelete {
            memory: MemoryStore,
            entered: tokio::sync::Notify,
            gate: std::sync::Mutex<Option<std::sync::mpsc::Receiver<()>>>,
        }
        impl Store for GatedDelete {
            fn load(&self) -> Result<Option<Vec<u8>>> {
                self.memory.load()
            }
            fn save(&self, data: &[u8]) -> Result<()> {
                self.memory.save(data)
            }
            fn delete(&self) -> Result<()> {
                self.entered.notify_one();
                self.gate
                    .lock()
                    .unwrap()
                    .take()
                    .unwrap()
                    .recv_timeout(std::time::Duration::from_secs(1))
                    .unwrap();
                self.memory.delete()
            }
        }
        let (release, gate) = std::sync::mpsc::channel();
        let store = Arc::new(GatedDelete {
            memory: MemoryStore::default(),
            entered: tokio::sync::Notify::new(),
            gate: std::sync::Mutex::new(Some(gate)),
        });
        let auth = Auth {
            api: Api::for_test_origin("http://127.0.0.1:9").unwrap(),
            store: store.clone(),
            operation_lock: Arc::new(Mutex::new(())),
            store_lock: Arc::new(Mutex::new(())),
            store_owner: Arc::new(std::sync::Mutex::new(None)),
            listeners: Arc::new(Mutex::new(BTreeMap::new())),
        };
        let original = auth.installation_id().await.unwrap();
        let copy = auth.clone();
        let cleanup = tokio::spawn(async move { copy.offline_logout().await });
        store.entered.notified().await;
        cleanup.abort();
        assert!(cleanup.await.unwrap_err().is_cancelled());
        let mut later = tokio::spawn(async move { auth.installation_id().await });
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(30), &mut later)
                .await
                .is_err()
        );
        release.send(()).unwrap();
        let replacement = later.await.unwrap().unwrap();
        assert_ne!(replacement, original);
        let durable: ProtectedState =
            serde_json::from_slice(&store.memory.load().unwrap().unwrap()).unwrap();
        assert_eq!(durable.installation_id, replacement);
    }
    #[tokio::test]
    async fn logout_failure_retains_protected_retry_and_blocks_execution() {
        let (auth, store, listener) = test_auth().await;
        let mut state = ProtectedState::fresh();
        state.device = Some(Token {
            access: "lmxda_prefix_secret".into(),
            refresh: "refresh".into(),
            subject: "device".into(),
            expires_at: now() + 3600,
        });
        auth.save(&state).await.unwrap();
        let server = tokio::spawn(async move {
            for status in [503, 200] {
                let (mut stream, _) = listener.accept().await.unwrap();
                let _ = read_request(&mut stream).await;
                respond(
                    &mut stream,
                    status,
                    if status == 200 {
                        json!({"data":{"revoked":true}})
                    } else {
                        json!({"error":{"code":"UNAVAILABLE"}})
                    },
                )
                .await;
            }
        });
        assert!(auth.logout().await.is_err());
        let durable: ProtectedState =
            serde_json::from_slice(&store.load().unwrap().unwrap()).unwrap();
        assert!(durable.logout_pending && durable.device.is_some());
        assert!(auth.credential("org").await.is_err());
        assert_eq!(auth.logout().await.unwrap()["revoked"], true);
        server.await.unwrap();
        let durable: ProtectedState =
            serde_json::from_slice(&store.load().unwrap().unwrap()).unwrap();
        assert!(durable.device.is_none() && !durable.logout_pending);
    }
    #[tokio::test]
    async fn definitive_enrollment_rejections_do_not_poison_authentication() {
        let (auth, store, listener) = test_auth().await;
        let mut state = ProtectedState::fresh();
        state.device = Some(Token {
            access: "lmxda_device_secret".into(),
            refresh: "device-refresh".into(),
            subject: "device".into(),
            expires_at: now() + 3600,
        });
        state.children.insert(
            "existing".into(),
            Token {
                access: "lmxr_existing_secret".into(),
                refresh: "existing-refresh".into(),
                subject: "existing-runner".into(),
                expires_at: now() + 3600,
            },
        );
        auth.save(&state).await.unwrap();
        let server = tokio::spawn(async move {
            for status in [403, 409, 422] {
                let (mut stream, _) = listener.accept().await.unwrap();
                let request = read_request(&mut stream).await;
                assert!(request.get("idempotencyKey").is_some());
                assert!(request.get("recovery").is_none());
                respond(
                    &mut stream,
                    status,
                    json!({"error":{"code":"ENROLLMENT_REJECTED"}}),
                )
                .await;
            }
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_request(&mut stream).await;
            assert!(request.get("recovery").is_none());
            respond(&mut stream, 201, json!({"data":{"enrolled":true,"runner":{"id":"new-runner"},"child":{"accessToken":"lmxr_new_secret","refreshToken":"new-refresh","expiresInSeconds":3600}}})).await;
        });
        for _ in 0..3 {
            let error = auth
                .select("rejected", &uuid::Uuid::new_v4().to_string())
                .await
                .unwrap_err();
            assert_eq!(error.to_string(), "ENROLLMENT_REJECTED");
            let durable: ProtectedState =
                serde_json::from_slice(&store.load().unwrap().unwrap()).unwrap();
            assert!(durable.pending.is_none());
            assert_eq!(auth.status().await.unwrap()["code"], "AUTHENTICATED");
            assert_eq!(
                auth.credential("existing").await.unwrap().subject,
                "existing-runner"
            );
        }
        assert_eq!(
            auth.select("new-org", &uuid::Uuid::new_v4().to_string())
                .await
                .unwrap()["enrolled"],
            true
        );
        server.await.unwrap();
        assert_eq!(
            auth.credential("new-org").await.unwrap().subject,
            "new-runner"
        );
    }
    #[tokio::test]
    async fn logout_uses_expired_historical_token_without_refresh_and_persists_intent() {
        let (auth, store, listener) = test_auth().await;
        let mut state = ProtectedState::fresh();
        state.device = Some(Token {
            access: "lmxda_historical_secret".into(),
            refresh: "spent-refresh".into(),
            subject: "device".into(),
            expires_at: 0,
        });
        state.pending = Some(Pending {
            target: Target::DeviceRefresh,
            route: "v2/device-authorities/refresh/".into(),
            body: json!({"refreshToken":"spent-refresh","proof":"spent-proof"}),
            started_at: now().saturating_sub(100),
            recovery_used: true,
            superseded: None,
        });
        auth.save(&state).await.unwrap();
        let server_store = store.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_request(&mut stream).await;
            assert_eq!(request, json!({})); // Refresh and recovery requests carry secrets.
            let durable: ProtectedState =
                serde_json::from_slice(&server_store.load().unwrap().unwrap()).unwrap();
            assert!(durable.logout_pending);
            assert!(durable.device.is_some() && durable.pending.is_some());
            respond(
                &mut stream,
                200,
                json!({"data":{"revoked":true,"alreadyRevoked":true}}),
            )
            .await;
        });
        assert_eq!(auth.logout().await.unwrap()["revoked"], true);
        server.await.unwrap();
        let durable: ProtectedState =
            serde_json::from_slice(&store.load().unwrap().unwrap()).unwrap();
        assert!(durable.device.is_none() && durable.pending.is_none() && !durable.logout_pending);
    }
    #[tokio::test(flavor = "current_thread")]
    async fn blocked_store_load_and_save_leave_runtime_responsive() {
        use std::sync::atomic::{AtomicBool, Ordering};
        struct GatedStore {
            memory: MemoryStore,
            gate_load: bool,
            gate: std::sync::Mutex<Option<std::sync::mpsc::Receiver<()>>>,
            entered: tokio::sync::Notify,
            emergency_release: AtomicBool,
        }
        impl GatedStore {
            fn pause(&self) {
                if let Some(gate) = self.gate.lock().unwrap().take() {
                    self.entered.notify_one();
                    // A bounded fallback prevents a regression from hanging the suite.
                    if gate
                        .recv_timeout(std::time::Duration::from_millis(500))
                        .is_err()
                    {
                        self.emergency_release.store(true, Ordering::SeqCst);
                    }
                }
            }
        }
        impl Store for GatedStore {
            fn load(&self) -> Result<Option<Vec<u8>>> {
                if self.gate_load {
                    self.pause();
                }
                self.memory.load()
            }
            fn save(&self, bytes: &[u8]) -> Result<()> {
                if !self.gate_load {
                    self.pause();
                }
                self.memory.save(bytes)
            }
        }
        for gate_load in [true, false] {
            let (release, gate) = std::sync::mpsc::channel();
            let store = Arc::new(GatedStore {
                memory: MemoryStore::default(),
                gate_load,
                gate: std::sync::Mutex::new(Some(gate)),
                entered: tokio::sync::Notify::new(),
                emergency_release: AtomicBool::new(false),
            });
            let auth = Auth {
                api: Api::for_test_origin("http://127.0.0.1:9").unwrap(),
                store: store.clone(),
                operation_lock: Arc::new(Mutex::new(())),
                store_lock: Arc::new(Mutex::new(())),
                store_owner: Arc::new(std::sync::Mutex::new(None)),
                listeners: Arc::new(Mutex::new(BTreeMap::new())),
            };
            let operation_auth = auth.clone();
            let operation = tokio::spawn(async move {
                if gate_load {
                    operation_auth.status().await
                } else {
                    operation_auth
                        .installation_id()
                        .await
                        .map(|id| json!({"installationId":id}))
                }
            });
            store.entered.notified().await;
            // This task represents credential-free status/IPC work on the same
            // single-thread runtime while the native credential operation is stalled.
            assert_eq!(
                tokio::spawn(async {
                    tokio::task::yield_now().await;
                    "responsive"
                })
                .await
                .unwrap(),
                "responsive"
            );
            assert!(!store.emergency_release.load(Ordering::SeqCst));
            if gate_load {
                release.send(()).unwrap();
                operation.await.unwrap().unwrap();
            } else {
                operation.abort();
                assert!(operation.await.unwrap_err().is_cancelled());
                let mut reader = tokio::spawn(async move { auth.status().await });
                assert!(
                    tokio::time::timeout(std::time::Duration::from_millis(30), &mut reader)
                        .await
                        .is_err()
                );
                release.send(()).unwrap();
                // The read must see the finished write, even though its original
                // caller was cancelled while the protected store was blocked.
                assert!(reader.await.unwrap().unwrap()["installationId"].is_string());
            }
        }
    }
    #[tokio::test]
    async fn pending_queue_time_does_not_preempt_server_recovery_window() {
        let (auth, store, listener) = test_auth().await;
        let mut state = ProtectedState::fresh();
        state.children.insert(
            "org".into(),
            Token {
                access: "lmxr_old_secret".into(),
                refresh: "original-refresh".into(),
                subject: "runner".into(),
                expires_at: 0,
            },
        );
        // Model a 31-second protected-store stall before a just-committed request
        // lost its response. The persisted queue time predates the remote operation.
        state.pending = Some(Pending {
            target: Target::ChildRefresh("org".into()),
            route: "v1/delegations/refresh/".into(),
            body: json!({"refreshToken":"original-refresh","proof":"original-proof"}),
            started_at: now().saturating_sub(31),
            recovery_used: false,
            superseded: None,
        });
        auth.save(&state).await.unwrap();
        let server_store = store.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_request(&mut stream).await;
            assert_eq!(
                request,
                json!({"refreshToken":"original-refresh","proof":"original-proof","recovery":true})
            );
            let durable: ProtectedState =
                serde_json::from_slice(&server_store.load().unwrap().unwrap()).unwrap();
            assert!(durable.pending.unwrap().recovery_used);
            respond(&mut stream,200,json!({"data":{"accessToken":"lmxr_new_secret","refreshToken":"replacement","expiresInSeconds":3600}})).await;
        });
        let reconciled = auth.reconcile().await.unwrap();
        assert_eq!(reconciled["reconciled"], true);
        assert_eq!(reconciled["authenticated"], false);
        assert_eq!(
            auth.credential("org").await.unwrap().token,
            "lmxr_new_secret"
        );
        server.await.unwrap();
        let durable: ProtectedState =
            serde_json::from_slice(&store.load().unwrap().unwrap()).unwrap();
        assert!(durable.pending.is_none());
    }
    #[tokio::test]
    async fn blocked_store_read_returns_typed_failure_and_retains_one_io_guard() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct BlockedRead {
            calls: AtomicUsize,
            release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
            entered: tokio::sync::Notify,
        }
        impl Store for BlockedRead {
            fn load(&self) -> Result<Option<Vec<u8>>> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                self.entered.notify_one();
                self.release.lock().unwrap().recv().unwrap();
                Ok(None)
            }
            fn save(&self, _: &[u8]) -> Result<()> {
                panic!("read failure must not write")
            }
        }
        let (release, receiver) = std::sync::mpsc::channel();
        let store = Arc::new(BlockedRead {
            calls: AtomicUsize::new(0),
            release: std::sync::Mutex::new(receiver),
            entered: tokio::sync::Notify::new(),
        });
        let auth = Auth {
            api: Api::for_test_origin("http://127.0.0.1:9").unwrap(),
            store: store.clone(),
            operation_lock: Arc::new(Mutex::new(())),
            store_lock: Arc::new(Mutex::new(())),
            store_owner: Arc::new(std::sync::Mutex::new(None)),
            listeners: Arc::new(Mutex::new(BTreeMap::new())),
        };
        let copy = auth.clone();
        let mut call = tokio::spawn(async move { copy.load().await });
        store.entered.notified().await;
        let result = tokio::time::timeout(Duration::from_secs(3), &mut call).await;
        // Always release the test-only OS substitute before asserting, including red-before.
        release.send(()).unwrap();
        if result.is_err() {
            call.await.unwrap().unwrap();
        }
        assert!(
            result.is_ok(),
            "credential read failed to return a bounded typed error"
        );
        assert_eq!(
            result.unwrap().unwrap().err().unwrap().to_string(),
            "STORE_UNAVAILABLE"
        );
        assert_eq!(store.calls.load(Ordering::SeqCst), 1);
    }
    fn auth_with_store(store: Arc<dyn Store>) -> Auth {
        Auth {
            api: Api::for_test_origin("http://127.0.0.1:9").unwrap(),
            store,
            operation_lock: Arc::new(Mutex::new(())),
            store_lock: Arc::new(Mutex::new(())),
            store_owner: Arc::new(std::sync::Mutex::new(None)),
            listeners: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
    #[tokio::test]
    async fn denied_store_reports_connection_category_without_starting_auth() {
        struct Denied;
        impl Store for Denied {
            fn load(&self) -> Result<Option<Vec<u8>>> {
                bail!("STORE_ACCESS_DENIED")
            }
            fn save(&self, _: &[u8]) -> Result<()> {
                panic!("denied read must not write")
            }
        }
        let auth = auth_with_store(Arc::new(Denied));
        let temp = tempfile::tempdir().unwrap();
        let daemon =
            crate::control::Daemon::new(temp.path().to_path_buf(), auth.api.clone(), auth.clone())
                .unwrap();
        let readiness = daemon.dispatch("status.get", json!({})).await.unwrap();
        assert_eq!(readiness["activeJobs"], 0);
        assert_eq!(readiness["draining"], false);
        // Local readiness does not attest to the separately read credential store.
        assert_eq!(auth.status().await.unwrap()["code"], "STORE_ACCESS_DENIED");
        let connection = auth.connection(None, 0).await;
        assert_eq!(connection["state"], "credential_store_unavailable");
        assert_eq!(
            connection["details"]["credentialStoreCode"],
            "STORE_ACCESS_DENIED"
        );
        assert!(connection["login"].is_null());
        assert_eq!(connection["actions"], json!([]));
        assert_eq!(
            auth.credential("org").await.err().unwrap().to_string(),
            "STORE_ACCESS_DENIED"
        );
    }
    #[tokio::test]
    async fn timed_out_write_retains_serialization_and_late_completion_cannot_overtake_logout() {
        struct Delayed {
            bytes: std::sync::Mutex<Option<Vec<u8>>>,
            writes: std::sync::atomic::AtomicUsize,
            release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
            entered: tokio::sync::Notify,
        }
        impl Store for Delayed {
            fn load(&self) -> Result<Option<Vec<u8>>> {
                Ok(self.bytes.lock().unwrap().clone())
            }
            fn save(&self, bytes: &[u8]) -> Result<()> {
                if self
                    .writes
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                    == 0
                {
                    self.entered.notify_one();
                    self.release.lock().unwrap().recv().unwrap();
                }
                *self.bytes.lock().unwrap() = Some(bytes.to_vec());
                Ok(())
            }
            fn delete(&self) -> Result<()> {
                *self.bytes.lock().unwrap() = None;
                Ok(())
            }
        }
        let (release, receiver) = std::sync::mpsc::channel();
        let store = Arc::new(Delayed {
            bytes: std::sync::Mutex::new(None),
            writes: std::sync::atomic::AtomicUsize::new(0),
            release: std::sync::Mutex::new(receiver),
            entered: tokio::sync::Notify::new(),
        });
        let auth = auth_with_store(store.clone());
        let copy = auth.clone();
        let operation = tokio::spawn(async move { copy.save(&ProtectedState::fresh()).await });
        store.entered.notified().await;
        assert_eq!(
            operation.await.unwrap().unwrap_err().to_string(),
            "STORE_OPERATION_PENDING"
        );
        assert_eq!(
            auth.offline_logout().await.unwrap_err().to_string(),
            "STORE_UNAVAILABLE"
        );
        assert_eq!(store.writes.load(std::sync::atomic::Ordering::SeqCst), 1);
        release.send(()).unwrap();
        assert_eq!(auth.offline_logout().await.unwrap()["revoked"], true);
        assert!(store.bytes.lock().unwrap().is_none());
        assert_eq!(auth.status().await.unwrap()["authenticated"], false);
    }
    #[tokio::test]
    async fn late_expired_read_is_discarded_and_concurrent_auth_does_not_repeat_native_io() {
        struct DelayedRead {
            calls: std::sync::atomic::AtomicUsize,
            release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
            entered: tokio::sync::Notify,
            bytes: Vec<u8>,
        }
        impl Store for DelayedRead {
            fn load(&self) -> Result<Option<Vec<u8>>> {
                if self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                    self.entered.notify_one();
                    self.release.lock().unwrap().recv().unwrap();
                    Ok(Some(self.bytes.clone()))
                } else {
                    Ok(None)
                }
            }
            fn save(&self, _: &[u8]) -> Result<()> {
                panic!("no late expired credential may initiate refresh")
            }
        }
        let mut state = ProtectedState::fresh();
        state.children.insert(
            "org".into(),
            Token {
                access: "expired-test-access".into(),
                refresh: "expired-test-refresh".into(),
                subject: "runner".into(),
                expires_at: 0,
            },
        );
        let (release, receiver) = std::sync::mpsc::channel();
        let store = Arc::new(DelayedRead {
            calls: std::sync::atomic::AtomicUsize::new(0),
            release: std::sync::Mutex::new(receiver),
            entered: tokio::sync::Notify::new(),
            bytes: serde_json::to_vec(&state).unwrap(),
        });
        let auth = auth_with_store(store.clone());
        let copy = auth.clone();
        let read = tokio::spawn(async move { copy.credential("org").await });
        store.entered.notified().await;
        let copy = auth.clone();
        let concurrent = tokio::spawn(async move { copy.credential("org").await });
        assert_eq!(
            read.await.unwrap().err().unwrap().to_string(),
            "STORE_UNAVAILABLE"
        );
        assert!(matches!(
            concurrent
                .await
                .unwrap()
                .err()
                .unwrap()
                .to_string()
                .as_str(),
            "STORE_UNAVAILABLE" | "AUTH_RECOVERY_PENDING"
        ));
        assert_eq!(store.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        release.send(()).unwrap();
        assert_eq!(
            auth.credential("org").await.err().unwrap().to_string(),
            "AUTH_REQUIRED"
        );
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn native_noninteractive_disposable_item_preserves_exact_matching_and_roundtrip() {
        use security_framework::os::macos::keychain::CreateOptions;
        let service = format!("app.loomex.runner.fixture.{}", uuid::Uuid::new_v4());
        let account = "disposable-native-fixture";
        let directory = tempfile::tempdir().unwrap();
        let keychain_path = directory.path().join("fixture.keychain-db");
        let keychain = CreateOptions::new()
            .password("disposable-fixture-password")
            .create(&keychain_path)
            .unwrap();
        // The fixture always names its own temporary keychain explicitly.
        let result = (|| -> Result<()> {
            keychain.add_generic_password(&service, account, b"disposable-fixture")?;
            if let Some(helper) = std::env::var_os("LOOMEX_NATIVE_FIXTURE_PROBE") {
                let mut probe = std::process::Command::new(helper)
                    .arg(&service)
                    .arg(account)
                    .arg(&keychain_path)
                    .stdout(std::process::Stdio::piped())
                    .spawn()?;
                let deadline = std::time::Instant::now() + Duration::from_secs(3);
                loop {
                    if probe.try_wait()?.is_some() {
                        break;
                    }
                    if std::time::Instant::now() >= deadline {
                        probe.kill()?;
                        probe.wait()?;
                        bail!("disposable native peer query stalled; isolated child stopped");
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                let output = probe.wait_with_output()?;
                ensure!(output.status.success(), "native fixture helper failed");
                let status: i32 = std::str::from_utf8(&output.stdout)?.trim().parse()?;
                ensure!(
                    matches!(status, 0 | -25300 | -25308 | -25315 | -25293),
                    "unexpected native fixture status"
                );
            }
            ensure!(
                keychain
                    .find_generic_password(&service, account)?
                    .0
                    .as_ref()
                    == b"disposable-fixture",
                "fixture read mismatch"
            );
            ensure!(
                keychain
                    .find_generic_password(&service, "different-fixture-account")
                    .unwrap_err()
                    .code()
                    == -25300,
                "account isolation"
            );
            ensure!(
                keychain
                    .find_generic_password(&format!("{service}.absent"), account)
                    .unwrap_err()
                    .code()
                    == -25300,
                "service isolation"
            );
            keychain.set_generic_password(&service, account, b"updated-disposable-fixture")?;
            ensure!(
                keychain
                    .find_generic_password(&service, account)?
                    .0
                    .as_ref()
                    == b"updated-disposable-fixture",
                "fixture update mismatch"
            );
            Ok(())
        })();
        let deleted = keychain
            .find_generic_password(&service, account)
            .map(|(_, item)| item.delete());
        result.unwrap();
        deleted.unwrap();
        assert_eq!(
            keychain
                .find_generic_password(&service, account)
                .unwrap_err()
                .code(),
            -25300
        );
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn native_osstatus_categories_do_not_infer_acl_or_global_lock() {
        assert_eq!(
            native_store_error(-25308).to_string(),
            "STORE_ACCESS_REQUIRED"
        );
        assert_eq!(
            native_store_error(-25315).to_string(),
            "STORE_ACCESS_REQUIRED"
        );
        assert_eq!(
            native_store_error(-25293).to_string(),
            "STORE_ACCESS_DENIED"
        );
        assert_eq!(native_store_error(-25243).to_string(), "STORE_UNAVAILABLE");
        assert_eq!(native_store_error(-36).to_string(), "STORE_UNAVAILABLE");
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn only_explicit_foreground_probe_allows_keychain_ui() {
        use core_foundation::{base::TCFType, string::CFString};
        use security_framework_sys::item::kSecUseAuthenticationUI;
        let key = unsafe { CFString::wrap_under_get_rule(kSecUseAuthenticationUI) };
        #[allow(deprecated)]
        let ordinary = noninteractive_password_options("fixture", "account")
            .query
            .iter()
            .filter(|(name, _)| name == &key)
            .count();
        #[allow(deprecated)]
        let foreground = foreground_password_options("fixture", "account")
            .query
            .iter()
            .filter(|(name, _)| name == &key)
            .count();
        assert_eq!(ordinary, 1);
        assert_eq!(foreground, 0);
    }
    #[test]
    fn runtime_disposal_retains_singleton_until_native_worker_actually_finishes() {
        use fs2::FileExt;
        struct DelayedDelete {
            release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
        }
        impl Store for DelayedDelete {
            fn load(&self) -> Result<Option<Vec<u8>>> {
                Ok(None)
            }
            fn save(&self, _: &[u8]) -> Result<()> {
                panic!("delete fixture cannot save")
            }
            fn delete(&self) -> Result<()> {
                self.release.lock().unwrap().recv().unwrap();
                Ok(())
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daemon.lock");
        let owner = Arc::new(
            std::fs::OpenOptions::new()
                .create(true)
                .truncate(false)
                .read(true)
                .write(true)
                .open(&path)
                .unwrap(),
        );
        owner.try_lock_exclusive().unwrap();
        let contender = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let (release, receiver) = std::sync::mpsc::channel();
        let auth = auth_with_store(Arc::new(DelayedDelete {
            release: std::sync::Mutex::new(receiver),
        }));
        auth.retain_store_owner(&owner);
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let error = runtime
            .block_on(auth.store_operation(true, |store| store.delete()))
            .unwrap_err();
        assert_eq!(error.to_string(), "STORE_OPERATION_PENDING");
        drop(owner);
        drop(auth);
        let before = std::time::Instant::now();
        runtime.shutdown_timeout(Duration::from_millis(20));
        let disposed_in = before.elapsed();
        let still_owned = contender.try_lock_exclusive().is_err();
        // Release our fake native worker even if an assertion is going to fail.
        release.send(()).unwrap();
        assert!(
            disposed_in < Duration::from_secs(1),
            "runtime disposal blocked"
        );
        assert!(still_owned, "late native delete lost singleton ownership");
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while contender.try_lock_exclusive().is_err() {
            assert!(
                std::time::Instant::now() < deadline,
                "worker did not release singleton after completion"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    #[tokio::test]
    async fn disposed_daemon_owner_cannot_start_late_native_io() {
        struct MustNotRun;
        impl Store for MustNotRun {
            fn load(&self) -> Result<Option<Vec<u8>>> {
                panic!("disposed owner cannot read")
            }
            fn save(&self, _: &[u8]) -> Result<()> {
                panic!("disposed owner cannot write")
            }
        }
        let auth = auth_with_store(Arc::new(MustNotRun));
        let owner = Arc::new(tempfile::tempfile().unwrap());
        auth.retain_store_owner(&owner);
        drop(owner);
        assert_eq!(
            auth.load().await.err().unwrap().to_string(),
            "STORE_UNAVAILABLE"
        );
        assert_eq!(
            auth.save(&ProtectedState::fresh())
                .await
                .unwrap_err()
                .to_string(),
            "STORE_UNAVAILABLE"
        );
    }
    const SCOPE_ORG: &str = "10000000-0000-4000-8000-000000000001";
    const SCOPE_RUNNER: &str = "10000000-0000-4000-8000-000000000002";
    const SCOPE_DEVICE: &str = "00000000-0000-4000-8000-000000000002";
    const SCOPE_DELEGATION: &str = "10000000-0000-4000-8000-000000000004";
    fn scope_self(granted: Value, effective: Value) -> Value {
        json!({"runner":{"id":SCOPE_RUNNER,"organizationId":SCOPE_ORG},"tokenScopes":effective,"scopeContext":{"organizationId":SCOPE_ORG,"runnerId":SCOPE_RUNNER,"deviceId":SCOPE_DEVICE,"delegationId":SCOPE_DELEGATION,"grantedScopes":granted,"effectiveTokenScopes":effective}})
    }
    async fn pending_upgrade_fixture(auth: &Auth, key: &str, scopes: &Value) -> ProtectedState {
        let mut state = auth.required().await.unwrap();
        state.persona_state.insert(format!("upgrade:{SCOPE_ORG}:{key}"), json!({
            "digest":runner_state::json_digest(&json!({"organizationId":SCOPE_ORG,"requestedScopes":scopes,"idempotencyKey":key})),
            "phase":"refresh_pending","organizationId":SCOPE_ORG,"runnerId":SCOPE_RUNNER,
            "deviceId":SCOPE_DEVICE,"delegationId":SCOPE_DELEGATION,
            "requestedScopes":scopes,"idempotencyKey":key
        }));
        auth.save(&state).await.unwrap();
        state
    }
    #[tokio::test]
    async fn persona_manage_scope_is_explicit_and_retains_exact_grant_and_owner() {
        assert_eq!(PERSONA_SCOPES.len(), 4);
        assert!(!PERSONA_SCOPES.contains(&"runner.personas.manage"));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api =
            Api::for_test_origin(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        let auth = Auth::test_enrolled(api, SCOPE_ORG, SCOPE_RUNNER);
        let key = "10000000-0000-4000-8000-000000000005";
        let scopes = json!(["runner.personas.manage"]);
        let journal_key = format!("upgrade:{SCOPE_ORG}:{key}");
        let mut state = pending_upgrade_fixture(&auth, key, &scopes).await;
        state.persona_state.get_mut(&journal_key).unwrap()["phase"] = json!("grant_pending");
        auth.save(&state).await.unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            assert_eq!(
                read_request(&mut stream).await,
                json!({"delegationId":SCOPE_DELEGATION,"requestedScopes":["runner.personas.manage"],"idempotencyKey":key})
            );
            respond(&mut stream,200,json!({"data":{"status":"denied","deviceId":SCOPE_DEVICE,"organizationId":SCOPE_ORG,"runnerId":SCOPE_RUNNER,"delegationId":SCOPE_DELEGATION,"requestedScopes":["runner.personas.manage"],"grantedScopes":["runner.personas.read"],"refreshRequired":false}})).await;
            assert!(
                tokio::time::timeout(Duration::from_millis(100), listener.accept())
                    .await
                    .is_err()
            );
        });
        let denied = auth.scope_upgrade(SCOPE_ORG, &scopes, key).await.unwrap();
        assert_eq!(denied["status"], "denied");
        assert_eq!(
            auth.scope_upgrade(SCOPE_ORG, &scopes, key).await.unwrap(),
            denied
        );
        assert_eq!(
            auth.scope_upgrade(
                SCOPE_ORG,
                &json!(["runner.personas.manage", "runner.personas.read"]),
                key
            )
            .await
            .unwrap_err()
            .to_string(),
            "IDEMPOTENCY_CONFLICT"
        );
        let mut changed = auth.required().await.unwrap();
        changed.children.get_mut(SCOPE_ORG).unwrap().subject =
            "10000000-0000-4000-8000-000000000009".into();
        auth.save(&changed).await.unwrap();
        assert_eq!(
            auth.scope_upgrade(SCOPE_ORG, &scopes, key)
                .await
                .unwrap_err()
                .to_string(),
            "AUTH_IDENTITY_CHANGED"
        );
        server.await.unwrap();
    }
    #[tokio::test]
    async fn persona_manage_scope_finalization_accepts_only_current_verified_grant() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api =
            Api::for_test_origin(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        let auth = Auth::test_enrolled(api, SCOPE_ORG, SCOPE_RUNNER);
        let key = "10000000-0000-4000-8000-000000000005";
        let scopes = json!(["runner.personas.manage"]);
        pending_upgrade_fixture(&auth, key, &scopes).await;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            assert!(read_request(&mut stream).await.is_null());
            let scopes = json!(["runner.personas.manage"]);
            respond(
                &mut stream,
                200,
                json!({"data":scope_self(scopes.clone(),scopes)}),
            )
            .await;
            assert!(
                tokio::time::timeout(Duration::from_millis(100), listener.accept())
                    .await
                    .is_err()
            );
        });
        let result = auth.scope_upgrade(SCOPE_ORG, &scopes, key).await.unwrap();
        assert_eq!(result["status"], "verified");
        assert_eq!(result["scopes"], scopes);
        assert_eq!(
            auth.scope_upgrade(SCOPE_ORG, &scopes, key).await.unwrap(),
            result
        );
        assert!(!result.to_string().contains("Token") && !result.to_string().contains("secret"));
        server.await.unwrap();
    }
    #[tokio::test]
    async fn persona_scope_self_recovers_lost_metadata_and_rejects_unverified_authority() {
        for case in [
            "lost",
            "implications",
            "insufficient",
            "legacy",
            "revoked",
            "organization",
            "runner",
            "device",
            "delegation",
            "local-generation",
            "malformed",
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let api = Api::for_test_origin(&format!("http://{}", listener.local_addr().unwrap()))
                .unwrap();
            let auth = Auth::test_enrolled(api, SCOPE_ORG, SCOPE_RUNNER);
            if case == "delegation" || case == "insufficient" || case == "revoked" {
                let mut state = auth.required().await.unwrap();
                let mut metadata = persona_credential_metadata(&json!({"organizationId":SCOPE_ORG,"runnerId":SCOPE_RUNNER,"deviceId":SCOPE_DEVICE,"delegationId":SCOPE_DELEGATION,"scopes":["runner.personas.read"]}),SCOPE_ORG).unwrap();
                if case == "delegation" {
                    metadata["delegationId"] = json!("10000000-0000-4000-8000-000000000009");
                }
                state
                    .persona_state
                    .insert(format!("credential:{SCOPE_ORG}"), metadata);
                auth.save(&state).await.unwrap();
            }
            let before = auth.store.load().unwrap();
            let copy = auth.clone();
            let operation = tokio::spawn(async move { copy.scope_status(SCOPE_ORG).await });
            let (mut stream, _) = listener.accept().await.unwrap();
            assert!(read_request(&mut stream).await.is_null());
            let mut data = scope_self(
                json!(["runner.personas.read"]),
                json!(["runner.personas.read"]),
            );
            match case {
                "implications" => {
                    data = scope_self(
                        json!(["runner.personas.chat", "runner.personas.memory.write"]),
                        json!([
                            "runner.personas.chat",
                            "runner.personas.read",
                            "runner.personas.memory.write",
                            "runner.personas.memory.read"
                        ]),
                    )
                }
                "insufficient" => data = scope_self(json!([]), json!([])),
                "legacy" => {
                    data.as_object_mut().unwrap().remove("scopeContext");
                }
                "organization" => {
                    data["runner"]["organizationId"] = json!("10000000-0000-4000-8000-000000000009")
                }
                "runner" => {
                    data["scopeContext"]["runnerId"] = json!("10000000-0000-4000-8000-000000000009")
                }
                "device" => {
                    data["scopeContext"]["deviceId"] = json!("10000000-0000-4000-8000-000000000009")
                }
                "malformed" => data["scopeContext"]["grantedScopes"] = json!([7]),
                "local-generation" => {
                    let mut state = auth.required().await.unwrap();
                    state.children.get_mut(SCOPE_ORG).unwrap().refresh =
                        "external-generation".into();
                    auth.store
                        .save(&serde_json::to_vec(&state).unwrap())
                        .unwrap();
                }
                _ => {}
            }
            if case == "revoked" {
                respond(
                    &mut stream,
                    401,
                    json!({"error":{"code":"RUNNER_TOKEN_INVALID"}}),
                )
                .await;
            } else {
                respond(&mut stream, 200, json!({"data":data})).await;
            }
            let result = operation.await.unwrap();
            match case {
                "lost" | "insufficient" | "implications" => {
                    let result = result.unwrap();
                    assert_eq!(result["status"], "verified");
                    assert_eq!(
                        result["scopes"],
                        match case {
                            "lost" => json!(["runner.personas.read"]),
                            "implications" => json!([
                                "runner.personas.chat",
                                "runner.personas.read",
                                "runner.personas.memory.write",
                                "runner.personas.memory.read"
                            ]),
                            _ => json!([]),
                        }
                    );
                    assert_eq!(result.as_object().unwrap().len(), 6);
                }
                "legacy" => assert_eq!(
                    result.unwrap_err().to_string(),
                    "AUTH_SCOPE_VERIFICATION_REQUIRED"
                ),
                "revoked" => {
                    assert_eq!(result.unwrap_err().to_string(), "RUNNER_TOKEN_INVALID")
                }
                "malformed" => assert_eq!(result.unwrap_err().to_string(), "INVALID_API_RESPONSE"),
                _ => assert_eq!(
                    result.unwrap_err().to_string(),
                    "AUTH_IDENTITY_CHANGED",
                    "{case}"
                ),
            }
            if case != "local-generation" {
                assert_eq!(auth.store.load().unwrap(), before, "{case}");
            }
            assert!(
                tokio::time::timeout(Duration::from_millis(30), listener.accept())
                    .await
                    .is_err(),
                "{case}"
            );
        }
    }
    #[tokio::test]
    async fn persona_scope_stale_access_rotates_once_without_grant_upgrade() {
        for still_stale in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let api = Api::for_test_origin(&format!("http://{}", listener.local_addr().unwrap()))
                .unwrap();
            let auth = Auth::test_enrolled(api, SCOPE_ORG, SCOPE_RUNNER);
            let installation = auth.installation_id().await.unwrap();
            let server = tokio::spawn(async move {
                let (mut first, _) = listener.accept().await.unwrap();
                assert!(read_request(&mut first).await.is_null());
                respond(
                    &mut first,
                    200,
                    json!({"data":scope_self(json!(["runner.personas.read"]),json!([]))}),
                )
                .await;
                let (mut refresh, _) = listener.accept().await.unwrap();
                let request = read_request(&mut refresh).await;
                assert_eq!(request["refreshToken"], "lmxrr_testprefix_testrefresh");
                assert!(request["proof"].is_string());
                assert!(request.get("requestedScopes").is_none());
                respond(&mut refresh,200,json!({"data":{"accessToken":"lmxr_new_secret","refreshToken":"new-refresh","expiresInSeconds":3600,"organizationId":SCOPE_ORG,"runnerId":SCOPE_RUNNER,"deviceId":SCOPE_DEVICE,"delegationId":SCOPE_DELEGATION,"scopes":[]}})).await;
                let (mut second, _) = listener.accept().await.unwrap();
                assert!(read_request(&mut second).await.is_null());
                respond(&mut second,200,json!({"data":scope_self(json!(["runner.personas.read"]),if still_stale {json!([])} else {json!(["runner.personas.read"])})})).await;
                assert!(
                    tokio::time::timeout(Duration::from_millis(30), listener.accept())
                        .await
                        .is_err()
                );
            });
            let result = auth.scope_status(SCOPE_ORG).await;
            if still_stale {
                assert_eq!(
                    result.unwrap_err().to_string(),
                    "AUTH_SCOPE_VERIFICATION_REQUIRED"
                );
            } else {
                assert_eq!(result.unwrap()["scopes"], json!(["runner.personas.read"]));
            }
            server.await.unwrap();
            assert_eq!(auth.installation_id().await.unwrap(), installation);
            let state = auth.required().await.unwrap();
            assert_eq!(state.children[SCOPE_ORG].subject, SCOPE_RUNNER);
            assert_eq!(state.children[SCOPE_ORG].refresh, "new-refresh");
            assert!(state.pending.is_none());
            assert!(
                state
                    .persona_state
                    .keys()
                    .all(|key| !key.starts_with("upgrade:"))
            );
        }
    }
    #[tokio::test]
    async fn persona_upgrade_metadata_free_rotation_finalizes_from_self_without_another_rotation() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api =
            Api::for_test_origin(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        let auth = Auth::test_enrolled(api, SCOPE_ORG, SCOPE_RUNNER);
        let key = "10000000-0000-4000-8000-000000000005";
        let scopes = json!(PERSONA_SCOPES);
        let current_scopes = json!([
            "runner.executions.cancel",
            "runner.executions.delete",
            "runner.human.read",
            "runner.human.resolve",
            "runner.jobs",
            "runner.read",
            "runner.workflows.read",
            "runner.workflows.run",
            "runner.personas.read",
            "runner.personas.chat",
            "runner.personas.memory.read",
            "runner.personas.memory.write"
        ]);
        let server_scopes = current_scopes.clone();
        let journal_key = format!("upgrade:{SCOPE_ORG}:{key}");
        let mut state = auth.required().await.unwrap();
        let installation = state.installation_id.clone();
        let private_key = state.private_key;
        state.persona_state.insert(journal_key.clone(), json!({
            "digest":runner_state::json_digest(&json!({"organizationId":SCOPE_ORG,"requestedScopes":scopes,"idempotencyKey":key})),
            "phase":"refresh_pending","organizationId":SCOPE_ORG,"runnerId":SCOPE_RUNNER,
            "deviceId":SCOPE_DEVICE,"delegationId":SCOPE_DELEGATION,
            "requestedScopes":scopes,"idempotencyKey":key
        }));
        auth.save(&state).await.unwrap();
        let server = tokio::spawn(async move {
            let mut rotations = 0;
            let mut self_reads = 0;
            while let Ok(Ok((mut stream, _))) =
                tokio::time::timeout(Duration::from_millis(100), listener.accept()).await
            {
                let body = read_request(&mut stream).await;
                if body.is_null() {
                    self_reads += 1;
                    respond(
                        &mut stream,
                        200,
                        json!({"data":scope_self(server_scopes.clone(),server_scopes.clone())}),
                    )
                    .await;
                } else {
                    assert!(body.get("refreshToken").is_some());
                    assert!(body.get("requestedScopes").is_none());
                    rotations += 1;
                    // Actual old v1 presenter omits all attachment metadata.
                    respond(&mut stream,200,json!({"data":{"accessToken":"lmxr_rotated_secret","refreshToken":"rotated-refresh","expiresInSeconds":3600}})).await;
                }
            }
            (rotations, self_reads)
        });
        // The approved grant's original rotation already succeeded.
        auth.refresh_child(&mut state, SCOPE_ORG).await.unwrap();
        assert!(state.pending.is_none());
        assert!(
            !state
                .persona_state
                .contains_key(&format!("credential:{SCOPE_ORG}"))
        );
        let result = auth.scope_upgrade(SCOPE_ORG, &scopes, key).await.unwrap();
        assert_eq!(result["status"], "verified");
        assert_eq!(result["scopes"], current_scopes);
        assert_eq!(
            auth.scope_upgrade(SCOPE_ORG, &scopes, key).await.unwrap(),
            result
        );
        assert_eq!(server.await.unwrap(), (1, 1));
        let durable = auth.required().await.unwrap();
        assert_eq!(durable.persona_state[&journal_key]["phase"], "verified");
        assert_eq!(durable.installation_id, installation);
        assert_eq!(durable.private_key, private_key);
        assert_eq!(durable.children[SCOPE_ORG].subject, SCOPE_RUNNER);
        assert_eq!(durable.children[SCOPE_ORG].refresh, "rotated-refresh");
        assert!(durable.pending.is_none());
    }
    #[tokio::test]
    async fn persona_upgrade_finalization_rejects_changed_or_unverified_authority_without_writes() {
        for case in [
            "organization",
            "runner",
            "device",
            "delegation",
            "legacy",
            "insufficient",
            "revoked",
            "generation",
            "overgrant",
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let api = Api::for_test_origin(&format!("http://{}", listener.local_addr().unwrap()))
                .unwrap();
            let auth = Auth::test_enrolled(api, SCOPE_ORG, SCOPE_RUNNER);
            let key = "10000000-0000-4000-8000-000000000005";
            let scopes = json!(["runner.personas.read"]);
            pending_upgrade_fixture(&auth, key, &scopes).await;
            let before = auth.store.load().unwrap();
            let copy = auth.clone();
            let args = scopes.clone();
            let operation =
                tokio::spawn(async move { copy.scope_upgrade(SCOPE_ORG, &args, key).await });
            let (mut stream, _) = listener.accept().await.unwrap();
            assert!(read_request(&mut stream).await.is_null(), "{case}");
            let mut data = scope_self(scopes.clone(), scopes.clone());
            match case {
                "organization" => {
                    data["scopeContext"]["organizationId"] =
                        json!("10000000-0000-4000-8000-000000000009")
                }
                "runner" => {
                    data["scopeContext"]["runnerId"] = json!("10000000-0000-4000-8000-000000000009")
                }
                "device" => {
                    data["scopeContext"]["deviceId"] = json!("10000000-0000-4000-8000-000000000009")
                }
                "delegation" => {
                    data["scopeContext"]["delegationId"] =
                        json!("10000000-0000-4000-8000-000000000009");
                    // Drift must fail before even a provably stale rotation.
                    data["scopeContext"]["effectiveTokenScopes"] = json!([]);
                    data["tokenScopes"] = json!([]);
                }
                "legacy" => {
                    data.as_object_mut().unwrap().remove("scopeContext");
                }
                "insufficient" => data = scope_self(json!([]), json!([])),
                "overgrant" => data["scopeContext"]["grantedScopes"] = json!([]),
                "generation" => {
                    let mut state = auth.required().await.unwrap();
                    state.children.get_mut(SCOPE_ORG).unwrap().refresh =
                        "external-generation".into();
                    auth.store
                        .save(&serde_json::to_vec(&state).unwrap())
                        .unwrap();
                }
                _ => {}
            }
            if case == "revoked" {
                respond(
                    &mut stream,
                    401,
                    json!({"error":{"code":"RUNNER_TOKEN_INVALID"}}),
                )
                .await;
            } else {
                respond(&mut stream, 200, json!({"data":data})).await;
            }
            let error = operation.await.unwrap().unwrap_err().to_string();
            assert_eq!(
                error,
                match case {
                    "legacy" | "insufficient" => "AUTH_SCOPE_VERIFICATION_REQUIRED",
                    "revoked" => "RUNNER_TOKEN_INVALID",
                    "overgrant" => "INVALID_API_RESPONSE",
                    _ => "AUTH_IDENTITY_CHANGED",
                },
                "{case}"
            );
            if case != "generation" {
                assert_eq!(auth.store.load().unwrap(), before, "{case}");
            }
            assert!(
                tokio::time::timeout(Duration::from_millis(30), listener.accept())
                    .await
                    .is_err(),
                "{case}"
            );
        }
    }
    #[tokio::test]
    async fn persona_upgrade_logout_fence_prevents_authority_read_and_receipt_write() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api =
            Api::for_test_origin(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        let auth = Auth::test_enrolled(api, SCOPE_ORG, SCOPE_RUNNER);
        let key = "10000000-0000-4000-8000-000000000005";
        let scopes = json!(PERSONA_SCOPES);
        let mut state = pending_upgrade_fixture(&auth, key, &scopes).await;
        state.logout_pending = true;
        auth.save(&state).await.unwrap();
        let before = auth.store.load().unwrap();
        assert_eq!(
            auth.scope_upgrade(SCOPE_ORG, &scopes, key)
                .await
                .unwrap_err()
                .to_string(),
            "LOGOUT_PENDING"
        );
        assert_eq!(auth.store.load().unwrap(), before);
        assert!(
            tokio::time::timeout(Duration::from_millis(30), listener.accept())
                .await
                .is_err()
        );
    }
    #[tokio::test]
    async fn persona_upgrade_stale_token_rotates_once_without_replaying_grant() {
        for still_stale in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let api = Api::for_test_origin(&format!("http://{}", listener.local_addr().unwrap()))
                .unwrap();
            let auth = Auth::test_enrolled(api, SCOPE_ORG, SCOPE_RUNNER);
            let key = "10000000-0000-4000-8000-000000000005";
            let scopes = json!(["runner.personas.read"]);
            pending_upgrade_fixture(&auth, key, &scopes).await;
            let server = tokio::spawn(async move {
                let (mut stale, _) = listener.accept().await.unwrap();
                assert!(read_request(&mut stale).await.is_null());
                respond(
                    &mut stale,
                    200,
                    json!({"data":scope_self(json!(["runner.personas.read"]),json!([]))}),
                )
                .await;
                let (mut refresh, _) = listener.accept().await.unwrap();
                let body = read_request(&mut refresh).await;
                assert_eq!(body["refreshToken"], "lmxrr_testprefix_testrefresh");
                assert!(body["proof"].is_string());
                assert!(body.get("requestedScopes").is_none());
                respond(&mut refresh,200,json!({"data":{"accessToken":"lmxr_rotated_secret","refreshToken":"rotated-refresh","expiresInSeconds":3600}})).await;
                let (mut current, _) = listener.accept().await.unwrap();
                assert!(read_request(&mut current).await.is_null());
                respond(&mut current,200,json!({"data":scope_self(json!(["runner.personas.read"]),if still_stale {json!([])} else {json!(["runner.personas.read"])})})).await;
                assert!(
                    tokio::time::timeout(Duration::from_millis(30), listener.accept())
                        .await
                        .is_err()
                );
            });
            let result = auth.scope_upgrade(SCOPE_ORG, &scopes, key).await;
            if still_stale {
                assert_eq!(
                    result.unwrap_err().to_string(),
                    "AUTH_SCOPE_VERIFICATION_REQUIRED"
                );
            } else {
                assert_eq!(result.unwrap()["status"], "verified");
            }
            server.await.unwrap();
            let state = auth.required().await.unwrap();
            assert!(state.pending.is_none());
            assert_eq!(state.children[SCOPE_ORG].refresh, "rotated-refresh");
            assert_eq!(
                state.persona_state[&format!("upgrade:{SCOPE_ORG}:{key}")]["phase"],
                if still_stale {
                    "refresh_pending"
                } else {
                    "verified"
                }
            );
        }
    }
    #[tokio::test]
    async fn persona_upgrade_concurrent_reconciliation_recovers_original_pending_proof_once() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api =
            Api::for_test_origin(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        let auth = Auth::test_enrolled(api, SCOPE_ORG, SCOPE_RUNNER);
        let key = "10000000-0000-4000-8000-000000000005";
        let scopes = json!(PERSONA_SCOPES);
        let mut state = pending_upgrade_fixture(&auth, key, &scopes).await;
        let refresh = state.children[SCOPE_ORG].refresh.clone();
        let proof = key_proof(&state.private_key, "refresh", &refresh);
        state.pending = Some(Pending {
            target: Target::ChildRefresh(SCOPE_ORG.into()),
            route: "v1/delegations/refresh/".into(),
            body: json!({"refreshToken":refresh,"proof":proof}),
            started_at: now(),
            recovery_used: false,
            superseded: None,
        });
        auth.save(&state).await.unwrap();
        let server = tokio::spawn(async move {
            let (mut recovery, _) = listener.accept().await.unwrap();
            assert_eq!(
                read_request(&mut recovery).await,
                json!({"refreshToken":refresh,"proof":proof,"recovery":true})
            );
            respond(&mut recovery,200,json!({"data":{"accessToken":"lmxr_recovered_secret","refreshToken":"recovered-refresh","expiresInSeconds":3600}})).await;
            let (mut authority, _) = listener.accept().await.unwrap();
            assert!(read_request(&mut authority).await.is_null());
            respond(
                &mut authority,
                200,
                json!({"data":scope_self(json!(PERSONA_SCOPES),json!(PERSONA_SCOPES))}),
            )
            .await;
            assert!(
                tokio::time::timeout(Duration::from_millis(30), listener.accept())
                    .await
                    .is_err()
            );
        });
        let (first, duplicate) = tokio::join!(
            auth.scope_upgrade(SCOPE_ORG, &scopes, key),
            auth.scope_upgrade(SCOPE_ORG, &scopes, key)
        );
        assert_eq!(first.as_ref().unwrap()["status"], "verified");
        assert_eq!(first.unwrap(), duplicate.unwrap());
        server.await.unwrap();
        let durable = auth.required().await.unwrap();
        assert!(durable.pending.is_none());
        assert_eq!(durable.children[SCOPE_ORG].refresh, "recovered-refresh");
        assert_eq!(
            durable.persona_state[&format!("upgrade:{SCOPE_ORG}:{key}")]["phase"],
            "verified"
        );
    }
    #[tokio::test]
    async fn persona_scope_upgrade_recovers_same_grant_and_same_child_without_logout() {
        let (auth, store, listener) = test_auth().await;
        let org = "10000000-0000-4000-8000-000000000001";
        let runner = "10000000-0000-4000-8000-000000000002";
        let device = SCOPE_DEVICE;
        let delegation = "10000000-0000-4000-8000-000000000004";
        let key = "10000000-0000-4000-8000-000000000005";
        let mut state = ProtectedState::fresh();
        state.device = Some(Token {
            access: "lmxda_device_secret".into(),
            refresh: "device-refresh".into(),
            subject: device.into(),
            expires_at: now() + 3600,
        });
        state.children.insert(
            org.into(),
            Token {
                access: "lmxr_child_secret".into(),
                refresh: "old-child-refresh".into(),
                subject: runner.into(),
                expires_at: now() + 3600,
            },
        );
        let installation = state.installation_id.clone();
        let private_key = state.private_key;
        auth.save(&state).await.unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let enrollment = read_request(&mut stream).await;
            assert_eq!(enrollment["idempotencyKey"], key);
            respond(&mut stream,200,json!({"data":{"deviceId":device,"runner":{"id":runner},"child":{"delegationId":delegation,"attachmentId":"attachment","scopes":[]}}})).await;
            let (mut first, _) = listener.accept().await.unwrap();
            let grant = read_request(&mut first).await;
            assert_eq!(
                grant,
                json!({"delegationId":delegation,"requestedScopes":["runner.personas.read"],"idempotencyKey":key})
            );
            drop(first);
            let (mut retry, _) = listener.accept().await.unwrap();
            assert_eq!(read_request(&mut retry).await, grant);
            respond(&mut retry,200,json!({"data":{"operationId":"operation","operation":"device_authority.persona_scope_upgrade","status":"granted","deviceId":device,"organizationId":org,"delegationId":delegation,"runnerId":runner,"requestedScopes":["runner.personas.read"],"grantedScopes":["runner.personas.read"],"refreshRequired":true}})).await;
            let (mut stale, _) = listener.accept().await.unwrap();
            assert!(read_request(&mut stale).await.is_null());
            respond(
                &mut stale,
                200,
                json!({"data":scope_self(json!(["runner.personas.read"]),json!([]))}),
            )
            .await;
            let (mut original, _) = listener.accept().await.unwrap();
            let refresh = read_request(&mut original).await;
            assert_eq!(refresh["refreshToken"], "old-child-refresh");
            drop(original);
            let (mut recovered, _) = listener.accept().await.unwrap();
            let recovery = read_request(&mut recovered).await;
            assert_eq!(recovery["refreshToken"], refresh["refreshToken"]);
            assert_eq!(recovery["proof"], refresh["proof"]);
            assert_eq!(recovery["recovery"], true);
            respond(&mut recovered,200,json!({"data":{"accessToken":"lmxr_newchild_secret","refreshToken":"new-child-refresh","expiresInSeconds":3600}})).await;
            for _ in 0..2 {
                let (mut self_read, _) = listener.accept().await.unwrap();
                assert!(read_request(&mut self_read).await.is_null());
                respond(&mut self_read,200,json!({"data":scope_self(json!(["runner.personas.read"]),json!(["runner.personas.read"]))})).await;
            }
        });
        assert_eq!(
            auth.scope_upgrade(org, &json!(["runner.personas.read"]), key)
                .await
                .unwrap_err()
                .to_string(),
            "NETWORK_AMBIGUOUS"
        );
        assert_eq!(
            auth.credential(org).await.unwrap().token,
            "lmxr_child_secret"
        );
        let result = auth
            .scope_upgrade(org, &json!(["runner.personas.read"]), key)
            .await
            .unwrap();
        assert_eq!(result["status"], "verified");
        assert_eq!(
            auth.scope_upgrade(org, &json!(["runner.personas.read"]), key)
                .await
                .unwrap(),
            result
        );
        assert_eq!(
            auth.scope_upgrade(org, &json!(["runner.personas.chat"]), key)
                .await
                .unwrap_err()
                .to_string(),
            "IDEMPOTENCY_CONFLICT"
        );
        let durable: ProtectedState =
            serde_json::from_slice(&store.load().unwrap().unwrap()).unwrap();
        assert_eq!(durable.installation_id, installation);
        assert_eq!(durable.private_key, private_key);
        assert_eq!(durable.children[org].subject, runner);
        assert_eq!(durable.children[org].refresh, "new-child-refresh");
        assert!(durable.pending.is_none());
        let status = auth.scope_status(org).await.unwrap();
        assert_eq!(status["scopes"], json!(["runner.personas.read"]));
        assert!(!status.to_string().contains("access") && !status.to_string().contains("refresh"));
        server.await.unwrap();
    }
    #[tokio::test]
    async fn legacy_persona_metadata_null_device_keeps_rotated_child_usable() {
        let (auth, store, listener) = test_auth().await;
        let mut state = ProtectedState::fresh();
        state.children.insert(
            "org".into(),
            Token {
                access: "lmxr_old_secret".into(),
                refresh: "old-refresh".into(),
                subject: "runner".into(),
                expires_at: 0,
            },
        );
        auth.save(&state).await.unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            read_request(&mut stream).await;
            respond(&mut stream,200,json!({"data":{"accessToken":"lmxr_new_secret","refreshToken":"new-refresh","expiresInSeconds":3600,"runnerId":"runner","organizationId":"org","delegationId":"10000000-0000-4000-8000-000000000004","deviceId":null,"scopes":["runner.jobs"]}})).await;
        });
        assert_eq!(
            auth.credential("org").await.unwrap().token,
            "lmxr_new_secret"
        );
        server.await.unwrap();
        let saved: ProtectedState =
            serde_json::from_slice(&store.load().unwrap().unwrap()).unwrap();
        assert_eq!(saved.children["org"].refresh, "new-refresh");
        assert!(saved.pending.is_none());
        assert!(!saved.persona_state.contains_key("credential:org"));
    }
    #[tokio::test]
    async fn cached_persona_upgrade_rejects_replaced_identity_and_logout_clears_journal() {
        let (auth, store, listener) = test_auth().await;
        let org = "10000000-0000-4000-8000-000000000001";
        let key = "10000000-0000-4000-8000-000000000005";
        let scopes = json!(["runner.personas.read"]);
        let mut state = ProtectedState::fresh();
        state.device = Some(Token {
            access: "lmxda_device_secret".into(),
            refresh: "device-refresh".into(),
            subject: "new-device".into(),
            expires_at: now() + 3600,
        });
        state.children.insert(
            org.into(),
            Token {
                access: "lmxr_child_secret".into(),
                refresh: "child-refresh".into(),
                subject: "new-runner".into(),
                expires_at: now() + 3600,
            },
        );
        state.persona_state.insert(format!("upgrade:{org}:{key}"),json!({"digest":runner_state::json_digest(&json!({"organizationId":org,"requestedScopes":scopes,"idempotencyKey":key})),"phase":"verified","deviceId":"old-device","runnerId":"old-runner","result":{"status":"verified"}}));
        auth.save(&state).await.unwrap();
        assert_eq!(
            auth.scope_upgrade(org, &scopes, key)
                .await
                .unwrap_err()
                .to_string(),
            "AUTH_IDENTITY_CHANGED"
        );
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            assert_eq!(read_request(&mut stream).await, json!({}));
            respond(&mut stream, 200, json!({"data":{"revoked":true}})).await;
        });
        auth.logout().await.unwrap();
        server.await.unwrap();
        let saved: ProtectedState =
            serde_json::from_slice(&store.load().unwrap().unwrap()).unwrap();
        assert!(saved.persona_state.is_empty() && saved.children.is_empty());
        assert!(auth.scope_upgrade(org, &scopes, key).await.is_err());
    }
}
