//! Manual-only destructive-within-disposable-VM native custody qualification.
use super::{
    journal::{Binding, Journal, Kind, Operation, Tombstone},
    load_state, persist_new,
    store::{NativeStore, Store},
};
use core_foundation::{
    array::{CFArray, CFArrayRef},
    base::{CFType, TCFType},
};
use security_framework::os::macos::keychain::{CreateOptions, SecKeychain};
use security_framework_sys::base::SecKeychainRef;
use std::{
    os::unix::fs::{MetadataExt, PermissionsExt},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
use uuid::Uuid;

unsafe extern "C" {
    fn SecKeychainCopySearchList(out: *mut CFArrayRef) -> i32;
    fn SecKeychainSetSearchList(list: CFArrayRef) -> i32;
    fn SecKeychainSetDefault(kc: SecKeychainRef) -> i32;
    fn SecKeychainDelete(kc: SecKeychainRef) -> i32;
    fn SecKeychainGetPreferenceDomain(domain: *mut i32) -> i32;
    fn SecKeychainCopyDomainSearchList(domain: i32, list: *mut CFArrayRef) -> i32;
    fn SecKeychainGetPath(kc: SecKeychainRef, length: *mut u32, path: *mut std::ffi::c_char)
    -> i32;
}

fn guard() {
    assert!(std::env::var("SHIKA_NATIVE_DISPOSABLE_VM").as_deref() == Ok("yes"));
    assert!(std::env::var("GITHUB_ACTIONS").as_deref() == Ok("true"));
    assert!(std::env::var("RUNNER_ENVIRONMENT").as_deref() == Ok("github-hosted"));
    assert!(std::env::var("RUNNER_OS").as_deref() == Ok("macOS"));
}
fn binding() -> Binding {
    Binding {
        api_origin: "https://api.example.invalid".into(),
        ui_origin: "https://ui.example.invalid".into(),
        installation_id: "native-fixture".into(),
        device_id: Uuid::from_u128(1),
        actor_id: None,
        workspace_id: None,
        connection_id: None,
    }
}
fn operation() -> Operation {
    Operation {
        kind: Kind::Start,
        operation_key: Uuid::from_u128(2),
        binding: binding(),
        method: "POST".into(),
        target: "/api/v2/pairings/".into(),
        body: b"{}".to_vec(),
        if_match: None,
        replacement_key: None,
    }
}
fn journal() -> Journal {
    Journal {
        version: 1,
        installation_id: "native-fixture".into(),
        device_id: Uuid::from_u128(1),
        selected: None,
        other_credentials: vec![],
        pending_pairing: None,
        completed_exchanges: vec![],
        completed_cancels: vec![],
        rejected_exchanges: vec![],
        completed_refreshes: vec![],
        denied_operations: vec![],
        tombstones: vec![],
        known_connections: vec![],
        pending: None,
        disconnect_pending: false,
    }
}
fn root_directory() -> std::path::PathBuf {
    let root =
        std::path::PathBuf::from(std::env::var_os("RUNNER_TEMP").expect("RUNNER_TEMP missing"));
    let meta = std::fs::symlink_metadata(&root).expect("RUNNER_TEMP invalid");
    assert!(
        root.is_absolute()
            && meta.is_dir()
            && !meta.file_type().is_symlink()
            && meta.uid() == unsafe { libc::geteuid() }
    );
    root.canonicalize().expect("RUNNER_TEMP canonicalization")
}
fn validate_child(root: &std::path::Path) {
    use std::io::Read;
    let mut input = String::new();
    std::io::stdin()
        .take(4096)
        .read_to_string(&mut input)
        .expect("child handshake");
    let (name, nonce) = input.split_once('\n').expect("child handshake format");
    assert!(
        name.starts_with("shika-native-") && !name.contains('/') && Uuid::parse_str(nonce).is_ok()
    );
    let dir = root.join(name);
    let md = std::fs::symlink_metadata(&dir).expect("fixture missing");
    assert!(
        md.is_dir()
            && !md.file_type().is_symlink()
            && md.uid() == unsafe { libc::geteuid() }
            && md.permissions().mode() & 0o077 == 0
    );
    assert_eq!(dir.canonicalize().expect("fixture canonicalization"), dir);
    let marker = dir.join("owner");
    let md = std::fs::symlink_metadata(&marker).expect("fixture marker missing");
    assert!(
        md.is_file()
            && !md.file_type().is_symlink()
            && md.uid() == unsafe { libc::geteuid() }
            && md.nlink() == 1
            && md.permissions().mode() & 0o077 == 0
    );
    assert!(std::fs::read_to_string(marker).expect("fixture marker") == nonce);
    let path = dir.join("native.keychain-db");
    let md = std::fs::symlink_metadata(&path).expect("fixture keychain missing");
    assert!(md.is_file() && !md.file_type().is_symlink() && md.uid() == unsafe { libc::geteuid() });
    // Only after filesystem validation, verify both native selections before any store call.
    verify_selection(&SecKeychain::open(path).expect("open fixture"), None);
}
// Security.framework returns opaque references: compare canonical file identities,
// never debug-print the references, paths, or any keychain contents.
fn keychain_path(kc: &SecKeychain) -> Option<std::path::PathBuf> {
    use std::os::unix::ffi::OsStringExt;
    let mut buffer = vec![0u8; 4096];
    let mut length = buffer.len() as u32;
    let status = unsafe {
        SecKeychainGetPath(
            kc.as_concrete_TypeRef(),
            &mut length,
            buffer.as_mut_ptr().cast(),
        )
    };
    if status != 0 || length == 0 || length as usize > buffer.len() {
        return None;
    }
    buffer.truncate(length as usize);
    if buffer.contains(&0) {
        return None;
    }
    let path = std::path::PathBuf::from(std::ffi::OsString::from_vec(buffer));
    if !path.is_absolute() {
        return None;
    }
    path.canonicalize().ok()
}
fn keychain_paths(list: &CFArray<CFType>) -> Option<Vec<std::path::PathBuf>> {
    let mut result = Vec::with_capacity(list.len() as usize);
    for item in list.iter() {
        if item.type_of() != SecKeychain::type_id() {
            return None;
        }
        let kc = unsafe { SecKeychain::wrap_under_get_rule(item.as_CFTypeRef() as SecKeychainRef) };
        result.push(keychain_path(&kc)?);
    }
    Some(result)
}
// Diagnostic reads only keychain references and path metadata inside the disposable VM.
// Every emitted value is a fixed category, count or boolean; paths are never printed.
fn diagnose_search(
    actual: &CFArray<CFType>,
    expected: &std::path::Path,
    prior: &CFArray<CFType>,
    prior_default: &SecKeychain,
) {
    let prior_paths = keychain_paths(prior);
    let prior_default_path = keychain_path(prior_default);
    let system_path = std::path::Path::new("/Library/Keychains/System.keychain")
        .canonicalize()
        .ok();
    let mut domain = -1i32;
    let domain_status = unsafe { SecKeychainGetPreferenceDomain(&mut domain) };
    let domain_label = if domain_status != 0 {
        "unavailable"
    } else {
        match domain {
            0 => "user",
            1 => "system",
            2 => "common",
            3 => "dynamic",
            _ => "unknown",
        }
    };
    eprintln!(
        "FIXTURE_DIAG preference_domain={domain_label} effective_count={}",
        actual.len()
    );
    let mut lists = Vec::new();
    for (id, label) in [(0, "user"), (1, "system"), (2, "common"), (3, "dynamic")] {
        let mut raw: CFArrayRef = std::ptr::null();
        let status = unsafe { SecKeychainCopyDomainSearchList(id, &mut raw) };
        if status != 0 || raw.is_null() {
            eprintln!("FIXTURE_DIAG domain={label} status=unavailable");
            lists.push(None);
        } else {
            let list = unsafe { CFArray::<CFType>::wrap_under_create_rule(raw) };
            eprintln!("FIXTURE_DIAG domain={label} count={}", list.len());
            lists.push(keychain_paths(&list));
        }
    }
    // Bound output, including for unexpected runner configurations.
    for (index, item) in actual.iter().take(16).enumerate() {
        let path = if item.type_of() == SecKeychain::type_id() {
            let kc =
                unsafe { SecKeychain::wrap_under_get_rule(item.as_CFTypeRef() as SecKeychainRef) };
            keychain_path(&kc)
        } else {
            None
        };
        if let Some(path) = path {
            let compare = |candidate: Option<&std::path::PathBuf>| match candidate {
                Some(value) if value == &path => "yes",
                Some(_) => "no",
                None => "unknown",
            };
            let prior = match &prior_paths {
                Some(v) if v.contains(&path) => "yes",
                Some(_) => "no",
                None => "unknown",
            };
            let member = |i: usize| match &lists[i] {
                Some(v) if v.contains(&path) => "yes",
                Some(_) => "no",
                None => "unknown",
            };
            eprintln!(
                "FIXTURE_DIAG entry={index} fixture={} prior={} prior_default={} known_system={} user={} system={} common={} dynamic={}",
                if path == expected { "yes" } else { "no" },
                prior,
                compare(prior_default_path.as_ref()),
                compare(system_path.as_ref()),
                member(0),
                member(1),
                member(2),
                member(3)
            );
        } else {
            eprintln!("FIXTURE_DIAG entry={index} class=path_unavailable");
        }
    }
    if actual.len() > 16 {
        eprintln!("FIXTURE_DIAG entries=truncated");
    }
}
fn verify_selection(opened: &SecKeychain, diagnostic: Option<(&CFArray<CFType>, &SecKeychain)>) {
    let expected = keychain_path(opened).expect("FIXTURE_PATH_UNAVAILABLE");
    let current = SecKeychain::default().expect("FIXTURE_DEFAULT_UNAVAILABLE");
    assert!(
        keychain_path(&current).as_ref() == Some(&expected),
        "FIXTURE_DEFAULT_MISMATCH"
    );
    let mut raw: CFArrayRef = std::ptr::null();
    assert_eq!(
        unsafe { SecKeychainCopySearchList(&mut raw) },
        0,
        "FIXTURE_SEARCH_UNAVAILABLE"
    );
    assert!(!raw.is_null(), "FIXTURE_SEARCH_UNAVAILABLE");
    let actual = unsafe { CFArray::<CFType>::wrap_under_create_rule(raw) };
    if let Some((prior, previous)) = diagnostic {
        diagnose_search(&actual, &expected, prior, previous);
    }
    assert_eq!(actual.len(), 1, "FIXTURE_SEARCH_COUNT");
    let paths = keychain_paths(&actual).expect("FIXTURE_SEARCH_PATH_UNAVAILABLE");
    assert!(paths.first() == Some(&expected), "FIXTURE_SEARCH_MISMATCH");
}

fn expected_state(count: usize) -> Journal {
    let mut state = journal();
    state.pending = Some(operation());
    state.tombstones = (0..count)
        .map(|i| Tombstone {
            operation_key: Uuid::from_u128(100 + i as u128),
            kind: Kind::Cancel,
            request_hash: "0".repeat(64),
            resource_id: None,
            outcome: "cancelled".into(),
        })
        .collect();
    state
}
fn same_state(a: &Journal, b: &Journal) -> bool {
    serde_json::to_vec(a).expect("serialize actual")
        == serde_json::to_vec(b).expect("serialize expected")
}
fn verify_child() {
    let value = load_state(&NativeStore)
        .expect("child load failed")
        .expect("child state missing");
    assert!(same_state(&value, &expected_state(256)));
}

// Armed before creation, because even a failed create may alter preferences.
struct Fixture {
    previous: SecKeychain,
    search: CFArray<CFType>,
    temporary: Option<SecKeychain>,
    attempted: bool,
    cleaned: bool,
}
impl Fixture {
    fn cleanup(&mut self) -> bool {
        if self.cleaned {
            return false;
        }
        let default_ok = unsafe { SecKeychainSetDefault(self.previous.as_concrete_TypeRef()) } == 0;
        let search_ok = unsafe { SecKeychainSetSearchList(self.search.as_concrete_TypeRef()) } == 0;
        let deletion_ok = if default_ok && search_ok {
            match &self.temporary {
                Some(kc) => unsafe { SecKeychainDelete(kc.as_concrete_TypeRef()) == 0 },
                None => !self.attempted,
            }
        } else {
            false
        };
        let mut raw: CFArrayRef = std::ptr::null();
        let status = unsafe { SecKeychainCopySearchList(&mut raw) };
        let search_verified = if status == 0 && !raw.is_null() {
            let actual = unsafe { CFArray::<CFType>::wrap_under_create_rule(raw) };
            match (keychain_paths(&actual), keychain_paths(&self.search)) {
                (Some(actual), Some(expected)) => actual == expected,
                _ => false,
            }
        } else {
            false
        };
        let default_verified = SecKeychain::default()
            .map(
                |v| match (keychain_path(&v), keychain_path(&self.previous)) {
                    (Some(actual), Some(expected)) => actual == expected,
                    _ => false,
                },
            )
            .unwrap_or(false);
        self.cleaned = true;
        default_ok && search_ok && deletion_ok && search_verified && default_verified
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if !self.cleaned && !self.cleanup() {
            eprintln!("native fixture cleanup failed; disposable VM must be discarded");
        }
    }
}
struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match self.0.try_wait() {
                Ok(Some(_)) => return,
                _ if Instant::now() >= deadline => {
                    eprintln!("child could not be reaped; discard disposable VM");
                    std::process::abort();
                }
                _ => std::thread::sleep(Duration::from_millis(20)),
            }
        }
    }
}

#[test]
#[ignore = "manual disposable GitHub-hosted macOS VM only"]
fn native_custody_disposable_ci() {
    guard();
    let root = root_directory();
    if std::env::var_os("SHIKA_NATIVE_CHILD").is_some() {
        validate_child(&root);
        let initial_ui = SecKeychain::user_interaction_allowed().expect("child UI state");
        let no_ui = if initial_ui {
            Some(SecKeychain::disable_user_interaction().expect("child disable UI"))
        } else {
            None
        };
        verify_child();
        drop(no_ui);
        assert!(
            SecKeychain::user_interaction_allowed().expect("child UI restore check") == initial_ui,
            "child UI restoration failed"
        );
        println!("SHIKA_NATIVE_RESTART_OK");
        return;
    }
    let directory = tempfile::Builder::new()
        .prefix("shika-native-")
        .tempdir_in(&root)
        .expect("fixture directory")
        .keep();
    let meta = std::fs::symlink_metadata(&directory).expect("fixture metadata");
    assert!(meta.uid() == unsafe { libc::geteuid() } && meta.permissions().mode() & 0o077 == 0);
    let nonce = Uuid::new_v4().to_string();
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut marker = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(directory.join("owner"))
        .expect("fixture marker");
    marker.write_all(nonce.as_bytes()).expect("marker write");
    drop(marker);
    let previous = SecKeychain::default().expect("VM default unavailable");
    let mut search_ref: CFArrayRef = std::ptr::null();
    assert_eq!(unsafe { SecKeychainCopySearchList(&mut search_ref) }, 0);
    assert!(!search_ref.is_null());
    let search = unsafe { CFArray::<CFType>::wrap_under_create_rule(search_ref) };
    let initial_ui = SecKeychain::user_interaction_allowed().expect("UI state");
    let no_ui = if initial_ui {
        Some(SecKeychain::disable_user_interaction().expect("disable UI"))
    } else {
        None
    };
    let mut fixture = Fixture {
        previous,
        search,
        temporary: None,
        attempted: false,
        cleaned: false,
    };
    let password = Uuid::new_v4().to_string();
    fixture.attempted = true;
    fixture.temporary = Some(
        CreateOptions::new()
            .password(&password)
            .prompt_user(false)
            .create(directory.join("native.keychain-db"))
            .expect("fixture keychain create"),
    );
    let temporary = fixture.temporary.as_ref().expect("fixture handle");
    let one = CFArray::from_CFTypes(&[temporary.clone()]);
    assert_eq!(
        unsafe { SecKeychainSetDefault(temporary.as_concrete_TypeRef()) },
        0
    );
    assert_eq!(
        unsafe { SecKeychainSetSearchList(one.as_concrete_TypeRef()) },
        0
    );
    verify_selection(temporary, Some((&fixture.search, &fixture.previous)));

    // Synthetic Loomex namespace sentinel, inside the fixture keychain only.
    use security_framework::passwords::{
        PasswordOptions, delete_generic_password_options, generic_password,
        set_generic_password_options,
    };
    fn scoped_options(service: &str, account: &str) -> PasswordOptions {
        use core_foundation::string::CFString;
        use security_framework_sys::item::kSecUseAuthenticationUI;
        unsafe extern "C" {
            static kSecUseAuthenticationUIFail: core_foundation::string::CFStringRef;
        }
        let mut options = PasswordOptions::new_generic_password(service, account);
        #[allow(deprecated)]
        options.query.push(unsafe {
            (
                CFString::wrap_under_get_rule(kSecUseAuthenticationUI),
                CFString::wrap_under_get_rule(kSecUseAuthenticationUIFail).into_CFType(),
            )
        });
        options
    }
    fn sentinel_options() -> PasswordOptions {
        scoped_options("app.loomex.runner.v1", "installation")
    }
    set_generic_password_options(b"synthetic-sentinel", sentinel_options())
        .expect("sentinel create");
    let store = NativeStore;
    assert!(store.load().expect("initial load").is_none());
    let mut state = journal();
    println!(
        "synthetic baseline journal: {} bytes",
        serde_json::to_vec(&state).expect("serialization").len()
    );
    persist_new(&store, &state).expect("initial save");
    assert!(persist_new(&store, &state).is_err());
    assert!(same_state(
        &load_state(&store).expect("reload").expect("missing"),
        &state
    ));
    state.begin(&store, operation()).expect("begin");
    assert!(same_state(
        &load_state(&store)
            .expect("pending load")
            .expect("pending missing"),
        &state
    ));
    state.begin(&store, operation()).expect("identical retry");
    let mut conflict = operation();
    conflict.operation_key = Uuid::from_u128(3);
    assert!(state.begin(&store, conflict).is_err());
    for count in [32usize, 256] {
        state = expected_state(count);
        let bytes = serde_json::to_vec(&state).expect("serialization");
        println!(
            "synthetic journal: {count} tombstones, {} bytes",
            bytes.len()
        );
        store.save(&bytes).expect("native overwrite");
        let reloaded = load_state(&store)
            .expect("native reload")
            .expect("state absent");
        assert!(same_state(&reloaded, &state));
    }
    // New process, same VM security session; only a nonsecret phase flag is inherited.
    let mut child = ChildGuard(
        Command::new(std::env::current_exe().expect("test executable"))
            .args([
                "--exact",
                "shika::native_custody::native_custody_disposable_ci",
                "--ignored",
                "--nocapture",
            ])
            .env("SHIKA_NATIVE_CHILD", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn child"),
    );
    let name = directory
        .file_name()
        .expect("fixture name")
        .to_str()
        .expect("fixture name utf8");
    write!(
        child.0.stdin.take().expect("child stdin"),
        "{name}\n{nonce}"
    )
    .expect("child handshake write");
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(status) = child.0.try_wait().expect("child status") {
            assert!(status.success(), "child restart failed");
            use std::io::Read;
            let mut output = String::new();
            child
                .0
                .stdout
                .take()
                .expect("child output")
                .read_to_string(&mut output)
                .expect("child output read");
            assert!(
                output.contains("SHIKA_NATIVE_RESTART_OK"),
                "child test did not run"
            );
            break;
        }
        assert!(Instant::now() < deadline, "child restart timeout");
        std::thread::sleep(Duration::from_millis(20));
    }
    drop(child);
    assert!(generic_password(sentinel_options()).expect("sentinel load") == b"synthetic-sentinel");
    // Exact Shika tuple in the exclusive disposable keychain/search list.
    delete_generic_password_options(scoped_options(
        "app.shika.loomex.runner.v1",
        "protected-state",
    ))
    .expect("Shika delete");
    assert!(store.load().expect("post-delete load").is_none());
    assert!(
        generic_password(sentinel_options()).expect("sentinel after delete")
            == b"synthetic-sentinel"
    );
    delete_generic_password_options(sentinel_options()).expect("sentinel delete");
    assert!(
        fixture.cleanup(),
        "restore or fixture deletion failed; VM must be discarded"
    );
    std::fs::remove_file(directory.join("owner")).expect("remove marker");
    std::fs::remove_dir(&directory).expect("fixture directory not empty");
    drop(no_ui);
    assert!(
        SecKeychain::user_interaction_allowed().expect("UI restore check") == initial_ui,
        "UI restoration failed"
    );
    println!("SHIKA_NATIVE_CUSTODY_OK");
}
