use crate::api::{Api, SignedCredential, key_proof, now};
use anyhow::{Result, anyhow, bail, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Arc};
use tokio::sync::Mutex;

const SERVICE: &str = "app.loomex.runner.v1";
const ACCOUNT: &str = "installation";
trait Store: Send + Sync {
    fn load(&self) -> Result<Option<Vec<u8>>>;
    fn save(&self, data: &[u8]) -> Result<()>;
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
#[derive(Clone, Serialize, Deserialize)]
struct Login {
    key: String,
    runner_name: String,
    device_code: Option<String>,
    user_code: Option<String>,
    verification_uri: Option<String>,
    expires_at: u64,
    interval_seconds: u64,
    next_poll_at: u64,
}
#[derive(Clone, Serialize, Deserialize)]
enum Target {
    Bootstrap,
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
    recovery_used: bool,
}
impl Pending {
    fn can_recover(&self) -> bool {
        // started_at records when persistence was queued, not when the request
        // reached the server. A blocked Keychain write or process restart makes
        // that timestamp unsuitable for enforcing the server's 30-second window.
        // The backend validates expiry; the protected flag limits us to one replay.
        !self.recovery_used
    }
}
#[derive(Serialize, Deserialize)]
struct ProtectedState {
    installation_id: String,
    private_key: [u8; 32],
    device: Option<Token>,
    children: BTreeMap<String, Token>,
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
}
impl Auth {
    #[cfg(test)]
    pub(crate) fn test_unauthed(api: Api) -> Self {
        Self {
            api,
            store: Arc::new(MemoryStore::default()),
            lock: Arc::new(Mutex::new(())),
            store_lock: Arc::new(Mutex::new(())),
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
            if login.key == key && login.device_code.is_some() && login.expires_at > now() {
                return Ok(login_projection(login));
            }
            ensure!(
                login.key == key || login.expires_at <= now(),
                "LOGIN_ALREADY_PENDING"
            );
        }
        state.login = Some(Login {
            key: key.into(),
            runner_name: runner_name.into(),
            device_code: None,
            user_code: None,
            verification_uri: None,
            expires_at: now().saturating_add(600),
            interval_seconds: 5,
            next_poll_at: 0,
        });
        self.save(&state).await?;
        let public_key = URL_SAFE_NO_PAD.encode(
            SigningKey::from_bytes(&state.private_key)
                .verifying_key()
                .as_bytes(),
        );
        let data = self.api.request("POST","v2/device-authorities/start/",Some(json!({"installId":state.installation_id,"runnerName":runner_name,"publicKey":public_key})),None,Some(key)).await?;
        let user_code = field(&data, "userCode")?;
        let uri = self
            .api
            .verification_uri(&field(&data, "verificationUri")?, &user_code)?;
        state.login = Some(Login {
            key: key.into(),
            runner_name: runner_name.into(),
            device_code: Some(field(&data, "deviceCode")?),
            user_code: Some(user_code),
            verification_uri: Some(uri),
            expires_at: expiry(&data)?,
            interval_seconds: data["intervalSeconds"].as_u64().unwrap_or(5).max(1),
            next_poll_at: 0,
        });
        self.save(&state).await?;
        Ok(login_projection(state.login.as_ref().unwrap()))
    }
    pub async fn poll(&self, key: &str) -> Result<Value> {
        ensure!((16..=256).contains(&key.len()), "INVALID_IDEMPOTENCY_KEY");
        let _guard = self.lock.lock().await;
        let mut state = self.required().await?;
        Self::allowed(&state)?;
        if state.pending.is_some() {
            self.recover(&mut state).await?;
        }
        if state.device.is_some() {
            return Ok(json!({"status":"authenticated","authenticated":true}));
        }
        let login = state
            .login
            .as_mut()
            .ok_or_else(|| anyhow!("LOGIN_REQUIRED"))?;
        ensure!(login.expires_at > now(), "LOGIN_EXPIRED");
        if now() < login.next_poll_at {
            return Ok(
                json!({"status":"pending","pending":true,"retryAfterSeconds":login.next_poll_at-now()}),
            );
        }
        let device_code = login
            .device_code
            .clone()
            .ok_or_else(|| anyhow!("LOGIN_REQUIRED"))?;
        login.next_poll_at = now().saturating_add(login.interval_seconds);
        self.save(&state).await?;
        let data = self
            .api
            .request(
                "POST",
                "v2/device-authorities/token/",
                Some(json!({"deviceCode":device_code})),
                None,
                None,
            )
            .await?;
        if data["pending"] == true {
            return Ok(json!({"status":"pending","pending":true}));
        }
        let grant = field(&data, "bootstrapGrant")?;
        let proof = key_proof(&state.private_key, "device-bootstrap", &grant);
        self.begin(
            &mut state,
            Target::Bootstrap,
            "v2/device-authorities/bootstrap/".into(),
            json!({"bootstrapGrant":grant,"proof":proof}),
        )
        .await?;
        Ok(json!({"status":"authenticated","authenticated":true}))
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
        let orgs = data["organizations"].as_array().ok_or_else(|| anyhow!("INVALID_API_RESPONSE"))?.iter().map(|org| json!({"id":org["id"],"name":org["name"],"slug":org["slug"],"enrolled":org["enrolled"],"runner":org.get("runner").filter(|r|!r.is_null()).map(|r|json!({"id":r["id"],"name":r["name"]}))})).collect::<Vec<_>>();
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
    pub async fn logout(&self) -> Result<Value> {
        let _guard = self.lock.lock().await;
        let Some(mut state) = self.load().await? else {
            return Ok(json!({"revoked":true,"alreadyLoggedOut":true}));
        };
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
    json!({"status":"pending","pending":true,"userCode":login.user_code,"verificationUri":login.verification_uri,"expiresAt":login.expires_at,"intervalSeconds":login.interval_seconds})
}

#[cfg(test)]
mod tests {
    use super::*;
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
        assert!(!restored.pending.unwrap().can_recover());
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
            device_code: Some("SECRET".into()),
            user_code: Some("CODE".into()),
            verification_uri: Some("https://example.com".into()),
            expires_at: 0,
            interval_seconds: 5,
            next_poll_at: 0,
        };
        assert!(!login_projection(&login).to_string().contains("SECRET"));
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
        };
        (auth, store, listener)
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
