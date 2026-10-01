//! Keep macOS awake only while this process owns active local execution.
//!
//! The assertion prevents *idle* system sleep. It deliberately does not prevent
//! explicit sleep, lid-close/clamshell sleep, or system shutdown. A shared
//! assertion covers overlapping executions and is released with the last guard.

use std::sync::{Mutex, OnceLock};

trait AssertionBackend: Send + Sync {
    fn create(&self) -> Result<u32, ()>;
    fn release(&self, assertion_id: u32) -> Result<(), ()>;
}

#[derive(Default)]
struct AssertionState {
    holders: usize,
    assertion_id: Option<u32>,
}

struct AssertionManager<B: AssertionBackend> {
    backend: B,
    state: Mutex<AssertionState>,
}

impl<B: AssertionBackend> AssertionManager<B> {
    const RELEASE_ATTEMPTS: usize = 3;

    fn new(backend: B) -> Self {
        Self {
            backend,
            state: Mutex::new(AssertionState::default()),
        }
    }

    fn acquire(&self) -> Result<AssertionLease<'_, B>, ()> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let next_holders = state.holders.checked_add(1).ok_or(())?;
        if state.holders == 0 && state.assertion_id.is_none() {
            state.assertion_id = Some(self.backend.create()?);
        }
        state.holders = next_holders;
        Ok(AssertionLease { manager: self })
    }

    fn release(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        debug_assert!(state.holders > 0);
        state.holders -= 1;
        if state.holders == 0 {
            if let Some(assertion_id) = state.assertion_id {
                for _ in 0..Self::RELEASE_ATTEMPTS {
                    if self.backend.release(assertion_id).is_ok() {
                        state.assertion_id = None;
                        return;
                    }
                }
                // Keep the ID so later work reuses this assertion and retries
                // its release instead of stacking another native assertion.
                // Native diagnostics can contain private machine details, so
                // this fixed category is the only emitted detail.
                eprintln!("RUNNER_IDLE_SLEEP_ASSERTION_RELEASE_PENDING");
            }
        }
    }
}

struct AssertionLease<'a, B: AssertionBackend> {
    manager: &'a AssertionManager<B>,
}

impl<B: AssertionBackend> Drop for AssertionLease<'_, B> {
    fn drop(&mut self) {
        self.manager.release();
    }
}

static MANAGER: OnceLock<AssertionManager<NativeBackend>> = OnceLock::new();

/// An optional idle-sleep assertion for the lifetime of one active execution.
///
/// Acquire immediately before local work begins and retain this value until its
/// child processes have been stopped/reaped. Failure is diagnostic only: it does
/// not change lease, cancellation, or execution decisions. Dropping the guard
/// also releases its share during error and panic unwinding.
pub struct IdleSleepGuard {
    _lease: Option<AssertionLease<'static, NativeBackend>>,
}

impl IdleSleepGuard {
    pub fn acquire() -> Self {
        let manager = MANAGER.get_or_init(|| AssertionManager::new(NativeBackend));
        match manager.acquire() {
            Ok(lease) => Self {
                _lease: Some(lease),
            },
            Err(()) => {
                eprintln!("RUNNER_IDLE_SLEEP_ASSERTION_CREATE_FAILED");
                Self { _lease: None }
            }
        }
    }
}

struct NativeBackend;

#[cfg(target_os = "macos")]
impl AssertionBackend for NativeBackend {
    fn create(&self) -> Result<u32, ()> {
        use std::ffi::c_void;
        use std::ptr;

        type CFStringRef = *const c_void;
        const UTF8: u32 = 0x0800_0100;

        #[link(name = "CoreFoundation", kind = "framework")]
        unsafe extern "C" {
            fn CFStringCreateWithCString(
                allocator: *const c_void,
                text: *const i8,
                encoding: u32,
            ) -> CFStringRef;
            fn CFRelease(value: *const c_void);
        }
        #[link(name = "IOKit", kind = "framework")]
        unsafe extern "C" {
            fn IOPMAssertionCreateWithName(
                assertion_type: CFStringRef,
                assertion_level: u32,
                assertion_name: CFStringRef,
                assertion_id: *mut u32,
            ) -> i32;
        }

        // kIOPMAssertionTypePreventUserIdleSystemSleep and kIOPMAssertionLevelOn.
        let kind = unsafe {
            CFStringCreateWithCString(ptr::null(), c"PreventUserIdleSystemSleep".as_ptr(), UTF8)
        };
        if kind.is_null() {
            return Err(());
        }
        let reason = unsafe {
            CFStringCreateWithCString(ptr::null(), c"Loomex local execution".as_ptr(), UTF8)
        };
        if reason.is_null() {
            unsafe { CFRelease(kind) };
            return Err(());
        }
        let mut assertion_id = 0;
        let status = unsafe { IOPMAssertionCreateWithName(kind, 255, reason, &mut assertion_id) };
        unsafe {
            CFRelease(reason);
            CFRelease(kind);
        }
        (status == 0).then_some(assertion_id).ok_or(())
    }

    fn release(&self, assertion_id: u32) -> Result<(), ()> {
        #[link(name = "IOKit", kind = "framework")]
        unsafe extern "C" {
            fn IOPMAssertionRelease(assertion_id: u32) -> i32;
        }
        (unsafe { IOPMAssertionRelease(assertion_id) } == 0)
            .then_some(())
            .ok_or(())
    }
}

#[cfg(not(target_os = "macos"))]
impl AssertionBackend for NativeBackend {
    fn create(&self) -> Result<u32, ()> {
        Ok(0)
    }

    fn release(&self, _assertion_id: u32) -> Result<(), ()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};

    #[derive(Default)]
    struct Counts {
        creates: AtomicUsize,
        release_attempts: AtomicUsize,
        successful_releases: AtomicUsize,
        fail_next_create: AtomicBool,
        fail_next_releases: AtomicUsize,
    }

    struct FakeBackend(Arc<Counts>);

    impl AssertionBackend for FakeBackend {
        fn create(&self) -> Result<u32, ()> {
            self.0.creates.fetch_add(1, Ordering::SeqCst);
            if self.0.fail_next_create.swap(false, Ordering::SeqCst) {
                Err(())
            } else {
                Ok(42)
            }
        }

        fn release(&self, assertion_id: u32) -> Result<(), ()> {
            assert_eq!(assertion_id, 42);
            self.0.release_attempts.fetch_add(1, Ordering::SeqCst);
            if self
                .0
                .fail_next_releases
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                    (remaining > 0).then(|| remaining - 1)
                })
                .is_ok()
            {
                Err(())
            } else {
                self.0.successful_releases.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        }
    }

    #[test]
    fn overlapping_work_shares_one_assertion_until_last_guard_drops() {
        let counts = Arc::new(Counts::default());
        let manager = Arc::new(AssertionManager::new(FakeBackend(counts.clone())));
        let both_active = Arc::new(Barrier::new(3));
        let finish = Arc::new(Barrier::new(3));
        let threads: Vec<_> = (0..2)
            .map(|_| {
                let manager = manager.clone();
                let both_active = both_active.clone();
                let finish = finish.clone();
                std::thread::spawn(move || {
                    let _guard = manager.acquire().unwrap();
                    both_active.wait();
                    finish.wait();
                })
            })
            .collect();
        both_active.wait();
        assert_eq!(counts.creates.load(Ordering::SeqCst), 1);
        assert_eq!(counts.successful_releases.load(Ordering::SeqCst), 0);
        finish.wait();
        for thread in threads {
            thread.join().unwrap();
        }
        assert_eq!(counts.successful_releases.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn unwind_releases_assertion() {
        let counts = Arc::new(Counts::default());
        let manager = AssertionManager::new(FakeBackend(counts.clone()));
        let result = std::panic::catch_unwind(|| {
            let _guard = manager.acquire().unwrap();
            panic!("simulated execution panic");
        });
        assert!(result.is_err());
        assert_eq!(counts.successful_releases.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn failed_create_does_not_claim_a_holder_and_next_work_retries() {
        let counts = Arc::new(Counts::default());
        counts.fail_next_create.store(true, Ordering::SeqCst);
        let manager = AssertionManager::new(FakeBackend(counts.clone()));
        assert!(manager.acquire().is_err());
        assert_eq!(counts.successful_releases.load(Ordering::SeqCst), 0);
        let guard = manager.acquire().unwrap();
        assert_eq!(counts.creates.load(Ordering::SeqCst), 2);
        drop(guard);
        assert_eq!(counts.successful_releases.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn failed_release_is_bounded_and_retried_without_duplicate_assertion() {
        let counts = Arc::new(Counts::default());
        counts.fail_next_releases.store(
            AssertionManager::<FakeBackend>::RELEASE_ATTEMPTS,
            Ordering::SeqCst,
        );
        let manager = AssertionManager::new(FakeBackend(counts.clone()));
        drop(manager.acquire().unwrap());
        assert_eq!(counts.creates.load(Ordering::SeqCst), 1);
        assert_eq!(
            counts.release_attempts.load(Ordering::SeqCst),
            AssertionManager::<FakeBackend>::RELEASE_ATTEMPTS
        );
        assert_eq!(counts.successful_releases.load(Ordering::SeqCst), 0);

        // A still-active assertion is shared by the next execution, not
        // replaced by a second native assertion.
        let guard = manager.acquire().unwrap();
        assert_eq!(counts.creates.load(Ordering::SeqCst), 1);
        drop(guard);
        assert_eq!(counts.release_attempts.load(Ordering::SeqCst), 4);
        assert_eq!(counts.successful_releases.load(Ordering::SeqCst), 1);
    }
}
