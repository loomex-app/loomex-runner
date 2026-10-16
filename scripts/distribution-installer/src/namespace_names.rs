//! Read-only filesystem naming semantics for future install namespaces.
use anyhow::{Context, Result, ensure};
use std::{ffi::OsStr, fs, path::Path};

#[derive(Clone, Copy)]
pub(super) struct Policy {
    pub case_sensitive: bool,
    pub canonical_unicode: bool,
}

pub(super) fn volume_policy(path: &Path) -> Result<Policy> {
    let mut existing = path;
    loop {
        match fs::symlink_metadata(existing) {
            Ok(_) => break,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                existing = existing.parent().context("namespace volume unavailable")?;
            }
            Err(error) => return Err(error.into()),
        }
    }
    platform::volume_policy(existing)
}
pub(super) fn equivalent(left: &OsStr, right: &OsStr, policy: Policy) -> Result<bool> {
    if left == right {
        return Ok(true);
    }
    platform::equivalent(left, right, policy)
}

#[cfg(target_os = "macos")]
mod platform {
    use super::*;
    use std::{
        ffi::{CStr, CString, c_void},
        os::unix::ffi::OsStrExt,
    };

    #[repr(C)]
    struct VolumeAttributes {
        length: u32,
        capabilities: libc::vol_capabilities_attr_t,
    }
    pub(super) fn volume_policy(path: &Path) -> Result<Policy> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        // These plain C records are initialized fully before calling the SDK.
        let mut request: libc::attrlist = unsafe { std::mem::zeroed() };
        request.bitmapcount = libc::ATTR_BIT_MAP_COUNT;
        request.volattr = libc::ATTR_VOL_INFO | libc::ATTR_VOL_CAPABILITIES;
        let mut response: VolumeAttributes = unsafe { std::mem::zeroed() };
        let result = unsafe {
            libc::getattrlist(
                path.as_ptr(),
                (&mut request as *mut libc::attrlist).cast(),
                (&mut response as *mut VolumeAttributes).cast(),
                std::mem::size_of::<VolumeAttributes>(),
                0,
            )
        };
        ensure!(result == 0, "filesystem naming capabilities unavailable");
        ensure!(
            response.length as usize == std::mem::size_of::<VolumeAttributes>(),
            "incomplete filesystem naming capabilities"
        );
        let index = libc::VOL_CAPABILITIES_FORMAT;
        ensure!(
            response.capabilities.valid[index] & libc::VOL_CAP_FMT_CASE_SENSITIVE != 0,
            "filesystem case policy unavailable"
        );
        let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
        ensure!(
            unsafe { libc::statfs(path.as_ptr(), &mut filesystem) } == 0,
            "filesystem type unavailable"
        );
        // statfs guarantees its fixed filesystem-name array is NUL terminated.
        let kind = unsafe { CStr::from_ptr(filesystem.f_fstypename.as_ptr()) }.to_bytes();
        Ok(Policy {
            case_sensitive: response.capabilities.capabilities[index]
                & libc::VOL_CAP_FMT_CASE_SENSITIVE
                != 0,
            canonical_unicode: matches!(kind, b"apfs" | b"hfs"),
        })
    }

    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFStringCreateWithBytes(
            allocator: *const c_void,
            bytes: *const u8,
            count: isize,
            encoding: u32,
            external: u8,
        ) -> *const c_void;
        fn CFStringCompare(left: *const c_void, right: *const c_void, options: usize) -> isize;
        fn CFRelease(value: *const c_void);
    }
    struct Text(*const c_void);
    impl Drop for Text {
        fn drop(&mut self) {
            unsafe { CFRelease(self.0) };
        }
    }
    impl Text {
        fn new(value: &OsStr) -> Result<Self> {
            let bytes = value
                .to_str()
                .context("non UTF-8 namespace component")?
                .as_bytes();
            let length = isize::try_from(bytes.len())?;
            let text = unsafe {
                CFStringCreateWithBytes(std::ptr::null(), bytes.as_ptr(), length, 0x08000100, 0)
            };
            ensure!(!text.is_null(), "namespace Unicode comparison unavailable");
            Ok(Self(text))
        }
    }
    pub(super) fn equivalent(left: &OsStr, right: &OsStr, policy: Policy) -> Result<bool> {
        if policy.case_sensitive && !policy.canonical_unicode {
            return Ok(false);
        }
        let left = Text::new(left)?;
        let right = Text::new(right)?;
        // CoreFoundation's canonical comparison is independent of user locale.
        // Never request diacritic/width folding or case folding on sensitive volumes.
        let flags = if policy.case_sensitive { 0 } else { 1 }
            | if policy.canonical_unicode { 16 } else { 0 };
        Ok(unsafe { CFStringCompare(left.0, right.0, flags) } == 0)
    }
}

#[cfg(not(target_os = "macos"))]
mod platform {
    use super::*;
    pub(super) fn volume_policy(_: &Path) -> Result<Policy> {
        Ok(Policy {
            case_sensitive: true,
            canonical_unicode: false,
        })
    }
    pub(super) fn equivalent(_: &OsStr, _: &OsStr, policy: Policy) -> Result<bool> {
        ensure!(
            policy.case_sensitive && !policy.canonical_unicode,
            "unsupported filesystem naming policy"
        );
        Ok(false)
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    #[test]
    fn unicode_aliases_and_case_sensitive_policy_remain_distinct() {
        let sensitive = Policy {
            case_sensitive: true,
            canonical_unicode: true,
        };
        let insensitive = Policy {
            case_sensitive: false,
            canonical_unicode: true,
        };
        assert!(equivalent(OsStr::new("Runner"), OsStr::new("runner"), insensitive).unwrap());
        assert!(!equivalent(OsStr::new("Runner"), OsStr::new("runner"), sensitive).unwrap());
        for policy in [sensitive, insensitive] {
            assert!(
                equivalent(OsStr::new("caf\u{e9}"), OsStr::new("cafe\u{301}"), policy).unwrap()
            );
            assert!(!equivalent(OsStr::new("cafe"), OsStr::new("caf\u{e9}"), policy).unwrap());
        }
    }
}
