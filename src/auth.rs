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
use std::{collections::BTreeMap, sync::Arc};
use tokio::sync::Mutex;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
};

const SERVICE: &str = "app.loomex.runner.v1";
const ACCOUNT: &str = "installation";
const BROWSER_AUTH_CSS: &str = include_str!("../assets/browser_authority.css");

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
        match security_framework::passwords::get_generic_password(SERVICE, ACCOUNT) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.code() == -25300 => Ok(None),
            Err(_) => bail!("STORE_UNAVAILABLE"),
        }
    }
    fn save(&self, data: &[u8]) -> Result<()> {
        security_framework::passwords::set_generic_password(SERVICE, ACCOUNT, data)
            .map_err(|_| anyhow!("STORE_UNAVAILABLE"))
    }
    fn delete(&self) -> Result<()> {
        match security_framework::passwords::delete_generic_password(SERVICE, ACCOUNT) {
            Ok(()) => Ok(()),
            Err(error) if error.code() == -25300 => Ok(()),
            Err(_) => bail!("STORE_UNAVAILABLE"),
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
        self.expires_at > now().saturating_add(60)
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
    started_at: u64,
    // Retained only to decode pre-0.3.35 Keychain records. Exact proof-bound
    // recovery is repeatable on compatible backends until the server deadline.
    #[serde(default)]
    recovery_used: bool,
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
        }
    }
}
#[derive(Clone)]
pub struct Auth {
    api: Api,
    store: Arc<dyn Store>,
    lock: Arc<Mutex<()>>,
    store_lock: Arc<Mutex<()>>,
    listeners: Arc<Mutex<BTreeMap<String, JoinHandle<()>>>>,
}
impl Auth {
    #[cfg(test)]
    pub(crate) fn test_unauthed(api: Api) -> Self {
        Self {
            api,
            store: Arc::new(MemoryStore::default()),
            lock: Arc::new(Mutex::new(())),
            store_lock: Arc::new(Mutex::new(())),
            listeners: Arc::new(Mutex::new(BTreeMap::new())),
        }
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
    pub fn new(api: Api) -> Result<Self> {
        Ok(Self {
            api,
            store: Arc::new(NativeStore),
            lock: Arc::new(Mutex::new(())),
            store_lock: Arc::new(Mutex::new(())),
            listeners: Arc::new(Mutex::new(BTreeMap::new())),
        })
    }
    async fn load(&self) -> Result<Option<ProtectedState>> {
        let store = self.store.clone();
        let io_guard = self.store_lock.clone().lock_owned().await;
        tokio::task::spawn_blocking(move || {
            let _io_guard = io_guard;
            store
                .load()?
                .map(|data| serde_json::from_slice(&data).map_err(|_| anyhow!("STORE_INVALID")))
                .transpose()
        })
        .await
        .map_err(|_| anyhow!("STORE_UNAVAILABLE"))?
    }
    async fn save(&self, state: &ProtectedState) -> Result<()> {
        let bytes = serde_json::to_vec(state).map_err(|_| anyhow!("STORE_INVALID"))?;
        let store = self.store.clone();
        // The blocking closure retains the guard even if its caller is cancelled.
        let io_guard = self.store_lock.clone().lock_owned().await;
        tokio::task::spawn_blocking(move || {
            let _io_guard = io_guard;
            store.save(&bytes)
        })
        .await
        .map_err(|_| anyhow!("STORE_UNAVAILABLE"))?
    }
    async fn required(&self) -> Result<ProtectedState> {
        self.load().await?.ok_or_else(|| anyhow!("AUTH_REQUIRED"))
    }
    fn allowed(state: &ProtectedState) -> Result<()> {
        ensure!(!state.logout_pending, "LOGOUT_PENDING");
        Ok(())
    }
    pub async fn installation_id(&self) -> Result<String> {
        let _guard = self.lock.lock().await;
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
        let _guard = self.lock.lock().await;
        let Some(state) = self.load().await? else {
            return Ok(vec![]);
        };
        Self::allowed(&state)?;
        Ok(state.children.keys().cloned().collect())
    }
    pub async fn status(&self) -> Result<Value> {
        let _guard = self.lock.lock().await;
        match self.load().await {
            Err(error) => Ok(
                json!({"authenticated":false,"code":if error.to_string()=="STORE_UNAVAILABLE" {"STORE_UNAVAILABLE"} else {"STORE_INVALID"}}),
            ),
            Ok(None) => Ok(json!({"authenticated":false,"code":"AUTH_REQUIRED"})),
            Ok(Some(state)) => Ok(
                json!({"authenticated":state.device.is_some() && !state.logout_pending,"code":if state.logout_pending {"LOGOUT_PENDING"} else if state.pending.is_some() {"AUTH_RECOVERY_PENDING"} else if state.device.is_some() {"AUTHENTICATED"} else {"AUTH_REQUIRED"},"installationId":state.installation_id,"activeOrganization":state.active_organization,"organizations":state.children.keys().collect::<Vec<_>>(),"loginPending":state.login.is_some()}),
            ),
        }
    }
    /// Reconcile the exact durable authentication operation already stored in
    /// the Keychain. This never starts a new login, enrollment, or rotation.
    pub async fn reconcile(&self) -> Result<Value> {
        let _guard = self.lock.lock().await;
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
        let _guard = self.lock.lock().await;
        let unavailable = || {
            json!({
                "schemaVersion":"loomex.runner.connection/v2",
                "state":"credential_store_unavailable",
                "organization":{"status":"organization_required","selected":Value::Null},
                "organizations":[],
                "activeWork":active_work,
                "actions":[],
                "login":Value::Null,
            })
        };
        let Ok(stored) = self.load().await else {
            return unavailable();
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
            (
                "recovery_pending",
                vec!["auth.recover", "auth.logout"],
                Value::Null,
            )
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
        let _guard = self.lock.lock().await;
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
            .filter(|login| {
                login.key == key
                    && login.authorization_url.is_none()
                    && login.redirect_uri.is_some()
                    && login.expires_at > now()
            })
            .cloned();
        let (login, listener) = if let Some(login) = reused {
            let listener = if self.listeners.lock().await.contains_key(&login.flow_id) {
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
        self.save(&state).await?;
        Ok(login_projection(state.login.as_ref().unwrap()))
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
        let _guard = self.lock.lock().await;
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
        let _guard = self.lock.lock().await;
        let mut state = self.required().await?;
        let login = state
            .login
            .as_ref()
            .ok_or_else(|| anyhow!("LOGIN_REQUIRED"))?;
        ensure!(login.flow_id == flow_id, "LOGIN_FLOW_MISMATCH");
        let state_value = login
            .browser_state
            .as_deref()
            .ok_or_else(|| anyhow!("LOGIN_REQUIRED"))?;
        let proof = key_proof(&state.private_key, "browser-cancel", state_value);
        let body = json!({"transactionId":login.transaction_id,"state":state_value,"proof":proof});
        self.begin(
            &mut state,
            Target::BrowserCancel,
            "v2/browser-authorities/cancel/".into(),
            body,
        )
        .await?;
        if let Some(listener) = self.listeners.lock().await.remove(flow_id) {
            listener.abort()
        }
        Ok(json!({"canceled":true}))
    }
    pub async fn organizations(&self) -> Result<Value> {
        let _guard = self.lock.lock().await;
        let mut state = self.required().await?;
        self.ensure_device(&mut state).await?;
        let credential = state.device.as_ref().unwrap().signed(&state);
        let data = self
            .api
            .request("GET", "v2/organizations/", None, Some(&credential), None)
            .await?;
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
        let _guard = self.lock.lock().await;
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
        let _guard = self.lock.lock().await;
        let mut state = self.required().await?;
        Self::allowed(&state)?;
        if state.pending.is_some() {
            self.recover(&mut state).await?;
        }
        let child = state
            .children
            .get(org)
            .ok_or_else(|| anyhow!("ORGANIZATION_NOT_ENROLLED"))?;
        if !child.usable() {
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
        Ok(state
            .children
            .get(org)
            .ok_or_else(|| anyhow!("AUTH_REQUIRED"))?
            .signed(&state))
    }
    /// Returns the already-enrolled local child identity without refreshing,
    /// recovering, persisting, or contacting the backend.
    pub async fn current_child_identity(&self, org: &str) -> Result<(String, String)> {
        let _guard = self.lock.lock().await;
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
    pub async fn logout(&self) -> Result<Value> {
        let _guard = self.lock.lock().await;
        self.logout_locked().await
    }
    pub async fn offline_logout(&self) -> Result<Value> {
        let _guard = self.lock.lock().await;
        if let Some(mut state) = self.load().await? {
            if state.device.is_none() && (state.pending.is_some() || !state.children.is_empty()) {
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
        let store = self.store.clone();
        let io_guard = self.store_lock.clone().lock_owned().await;
        tokio::task::spawn_blocking(move || {
            // Cancellation cannot let another native store operation overtake deletion.
            let _io_guard = io_guard;
            store.delete()
        })
        .await
        .map_err(|_| anyhow!("STORE_UNAVAILABLE"))??;
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
                let state_value = login
                    .browser_state
                    .as_deref()
                    .ok_or_else(|| anyhow!("LOGIN_REQUIRED"))?;
                let proof = key_proof(&state.private_key, "browser-cancel", state_value);
                let body =
                    json!({"transactionId":login.transaction_id,"state":state_value,"proof":proof});
                self.begin(
                    &mut state,
                    Target::BrowserCancel,
                    "v2/browser-authorities/cancel/".into(),
                    body,
                )
                .await?;
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
        state.device = None;
        state.children.clear();
        state.organization_profiles.clear();
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
        let token = state
            .device
            .as_ref()
            .ok_or_else(|| anyhow!("AUTH_REQUIRED"))?;
        if !token.usable() {
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
        Ok(())
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
        let mut body = pending.body;
        if recovery {
            body["recovery"] = json!(true);
        }
        let credential = if matches!(pending.target, Target::Enroll(_)) {
            Some(
                state
                    .device
                    .as_ref()
                    .ok_or_else(|| anyhow!("AUTH_REQUIRED"))?
                    .signed(state),
            )
        } else {
            None
        };
        let data = match self
            .api
            .request(
                "POST",
                &pending.route,
                Some(body),
                credential.as_ref(),
                None,
            )
            .await
        {
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
                });
                self.save(state).await?;
                return Box::pin(self.transmit(state, false)).await;
            }
            Target::BrowserCancel => {
                if data["canceled"] != true {
                    state.pending = None;
                    self.save(state).await?;
                    bail!("LOGIN_ALREADY_APPROVED")
                }
                state.login = None;
            }
            Target::Bootstrap => {
                let device = &data["device"];
                state.device = Some(parse_token(device, field(device, "deviceId")?)?);
                state.login = None;
            }
            Target::DeviceRefresh => {
                let subject = state
                    .device
                    .as_ref()
                    .ok_or_else(|| anyhow!("AUTH_REQUIRED"))?
                    .subject
                    .clone();
                state.device = Some(parse_token(&data, subject)?);
            }
            Target::ChildRefresh(org) => {
                let subject = state
                    .children
                    .get(&org)
                    .ok_or_else(|| anyhow!("AUTH_REQUIRED"))?
                    .subject
                    .clone();
                state.children.insert(org, parse_token(&data, subject)?);
            }
            Target::Enroll(org) => {
                ensure!(
                    data.get("child").is_some(),
                    "ENROLLMENT_CREDENTIALS_UNAVAILABLE"
                );
                state.children.insert(
                    org,
                    parse_token(&data["child"], field(&data["runner"], "id")?)?,
                );
            }
        }
        state.pending = None;
        self.save(state).await
    }
}
fn field(value: &Value, name: &str) -> Result<String> {
    value
        .get(name)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("INVALID_API_RESPONSE"))
}
fn expiry(value: &Value) -> Result<u64> {
    now()
        .checked_add(
            value["expiresInSeconds"]
                .as_u64()
                .filter(|n| *n > 0)
                .ok_or_else(|| anyhow!("INVALID_API_RESPONSE"))?,
        )
        .ok_or_else(|| anyhow!("INVALID_API_RESPONSE"))
}
fn parse_token(value: &Value, subject: String) -> Result<Token> {
    Ok(Token {
        access: field(value, "accessToken")?,
        refresh: field(value, "refreshToken")?,
        subject,
        expires_at: expiry(value)?,
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
    async fn public_fixtures_use_only_memory() {
        let api = Api::for_test_origin("http://127.0.0.1:9").unwrap();
        let unauthed = Auth::test_unauthed(api.clone());
        assert_eq!(unauthed.status().await.unwrap()["code"], "AUTH_REQUIRED");
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
            lock: Arc::new(Mutex::new(())),
            store_lock: Arc::new(Mutex::new(())),
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
            lock: Arc::new(Mutex::new(())),
            store_lock: Arc::new(Mutex::new(())),
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
            lock: Arc::new(Mutex::new(())),
            store_lock: Arc::new(Mutex::new(())),
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
                lock: Arc::new(Mutex::new(())),
                store_lock: Arc::new(Mutex::new(())),
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
}
