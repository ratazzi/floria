//! Code-signature identity for a pid, via the macOS Security framework.
//!
//! `pid -> SecCodeCopyGuestWithAttributes -> SecCodeCopySigningInformation` yields the
//! signing identifier (bundle id) and Team Identifier. This is the stable, spoof-resistant
//! app identity the policy engine keys grants on (unlike the exe path).

use std::ffi::c_void;

use core_foundation::base::TCFType;
use core_foundation::dictionary::CFDictionary;
use core_foundation::number::CFNumber;
use core_foundation::string::CFString;
use core_foundation::url::CFURL;
use core_foundation_sys::base::{CFRelease, CFTypeRef};
use core_foundation_sys::dictionary::{CFDictionaryGetValue, CFDictionaryRef};
use core_foundation_sys::string::CFStringRef;
use core_foundation_sys::url::CFURLRef;
use std::path::Path;

type SecCodeRef = *const c_void;
type SecRequirementRef = *const c_void;
type SecStaticCodeRef = *const c_void;

const KSEC_CS_DEFAULT_FLAGS: u32 = 0;
const KSEC_CS_SIGNING_INFORMATION: u32 = 1 << 1;

#[link(name = "Security", kind = "framework")]
extern "C" {
    fn SecCodeCopyGuestWithAttributes(
        host: SecCodeRef,
        attributes: CFDictionaryRef,
        flags: u32,
        guest: *mut SecCodeRef,
    ) -> i32;
    fn SecCodeCopySigningInformation(
        code: SecCodeRef,
        flags: u32,
        information: *mut CFDictionaryRef,
    ) -> i32;
    fn SecCodeCheckValidity(
        code: SecCodeRef,
        flags: u32,
        requirement: SecRequirementRef,
    ) -> i32;
    fn SecCodeCopyDesignatedRequirement(
        code: SecStaticCodeRef,
        flags: u32,
        requirement: *mut SecRequirementRef,
    ) -> i32;
    fn SecRequirementCopyString(
        requirement: SecRequirementRef,
        flags: u32,
        text: *mut CFStringRef,
    ) -> i32;
    fn SecRequirementCreateWithString(
        text: CFStringRef,
        flags: u32,
        requirement: *mut SecRequirementRef,
    ) -> i32;
    fn SecStaticCodeCheckValidity(
        code: SecStaticCodeRef,
        flags: u32,
        requirement: SecRequirementRef,
    ) -> i32;
    fn SecStaticCodeCreateWithPath(
        path: CFURLRef,
        flags: u32,
        code: *mut SecStaticCodeRef,
    ) -> i32;
    static kSecGuestAttributePid: CFStringRef;
    static kSecCodeInfoTeamIdentifier: CFStringRef;
    static kSecCodeInfoIdentifier: CFStringRef;
}

pub(crate) fn designated_requirement(path: &Path) -> Result<String, String> {
    let path = std::fs::canonicalize(path)
        .map_err(|error| format!("resolving {}: {error}", path.display()))?;
    let is_directory = path.is_dir();
    let url = CFURL::from_path(&path, is_directory)
        .ok_or_else(|| format!("converting {} to a code URL", path.display()))?;

    // SAFETY: standard Security framework ownership rules. Every retained object is released
    // exactly once before returning, including all error paths after creation.
    unsafe {
        let mut code: SecStaticCodeRef = std::ptr::null();
        let status = SecStaticCodeCreateWithPath(
            url.as_concrete_TypeRef(),
            KSEC_CS_DEFAULT_FLAGS,
            &mut code,
        );
        if status != 0 || code.is_null() {
            return Err(format!(
                "SecStaticCodeCreateWithPath failed for {} (OSStatus {status})",
                path.display()
            ));
        }

        let status =
            SecStaticCodeCheckValidity(code, KSEC_CS_DEFAULT_FLAGS, std::ptr::null());
        if status != 0 {
            CFRelease(code as CFTypeRef);
            return Err(format!(
                "code signature is invalid for {} (OSStatus {status})",
                path.display()
            ));
        }

        let mut requirement: SecRequirementRef = std::ptr::null();
        let status = SecCodeCopyDesignatedRequirement(
            code,
            KSEC_CS_DEFAULT_FLAGS,
            &mut requirement,
        );
        CFRelease(code as CFTypeRef);
        if status != 0 || requirement.is_null() {
            return Err(format!(
                "copying designated requirement for {} failed (OSStatus {status})",
                path.display()
            ));
        }

        let mut text: CFStringRef = std::ptr::null();
        let status =
            SecRequirementCopyString(requirement, KSEC_CS_DEFAULT_FLAGS, &mut text);
        CFRelease(requirement as CFTypeRef);
        if status != 0 || text.is_null() {
            return Err(format!(
                "rendering designated requirement for {} failed (OSStatus {status})",
                path.display()
            ));
        }

        Ok(CFString::wrap_under_create_rule(text).to_string())
    }
}

pub(crate) fn satisfies_requirement(pid: i32, requirement_text: &str) -> Result<bool, String> {
    // SAFETY: standard Security framework usage. The live SecCode and compiled requirement
    // are retained by their create/copy calls and released before this function returns.
    unsafe {
        let code = copy_guest_code(pid)?;
        let text = CFString::new(requirement_text);
        let mut requirement: SecRequirementRef = std::ptr::null();
        let status = SecRequirementCreateWithString(
            text.as_concrete_TypeRef(),
            KSEC_CS_DEFAULT_FLAGS,
            &mut requirement,
        );
        if status != 0 || requirement.is_null() {
            CFRelease(code as CFTypeRef);
            return Err(format!(
                "compiling trusted requirement failed (OSStatus {status})"
            ));
        }

        let status = SecCodeCheckValidity(code, KSEC_CS_DEFAULT_FLAGS, requirement);
        CFRelease(requirement as CFTypeRef);
        CFRelease(code as CFTypeRef);
        Ok(status == 0)
    }
}

unsafe fn copy_guest_code(pid: i32) -> Result<SecCodeRef, String> {
    let key = CFString::wrap_under_get_rule(kSecGuestAttributePid);
    let val = CFNumber::from(pid);
    let attrs = CFDictionary::from_CFType_pairs(&[(key.as_CFType(), val.as_CFType())]);
    let mut code: SecCodeRef = std::ptr::null();
    let status = SecCodeCopyGuestWithAttributes(
        std::ptr::null(),
        attrs.as_concrete_TypeRef(),
        KSEC_CS_DEFAULT_FLAGS,
        &mut code,
    );
    if status != 0 || code.is_null() {
        Err(format!(
            "SecCodeCopyGuestWithAttributes failed for pid {pid} (OSStatus {status})"
        ))
    } else {
        Ok(code)
    }
}

#[derive(Debug, Default)]
pub struct CodeSignature {
    /// Team Identifier, e.g. "EQHXZ8M8AV". None for Apple platform binaries or unsigned code.
    pub team_id: Option<String>,
    /// Signing identifier / bundle id, e.g. "com.microsoft.VSCode".
    pub bundle_id: Option<String>,
}

/// Best-effort code-signature lookup for a running process. Never panics; returns empty on
/// any failure (unsigned, ESRCH, permission).
pub fn code_signature(pid: i32) -> CodeSignature {
    let empty = CodeSignature::default();
    // SAFETY: standard SecCode API usage. `code`/`info` are released before returning.
    unsafe {
        let key = CFString::wrap_under_get_rule(kSecGuestAttributePid);
        let val = CFNumber::from(pid);
        let attrs = CFDictionary::from_CFType_pairs(&[(key.as_CFType(), val.as_CFType())]);

        let mut code: SecCodeRef = std::ptr::null();
        let st = SecCodeCopyGuestWithAttributes(
            std::ptr::null(),
            attrs.as_concrete_TypeRef(),
            KSEC_CS_DEFAULT_FLAGS,
            &mut code,
        );
        if st != 0 || code.is_null() {
            return empty;
        }

        let mut info: CFDictionaryRef = std::ptr::null();
        let st = SecCodeCopySigningInformation(code, KSEC_CS_SIGNING_INFORMATION, &mut info);
        CFRelease(code as CFTypeRef);
        if st != 0 || info.is_null() {
            return empty;
        }

        let team_id = dict_string(info, kSecCodeInfoTeamIdentifier);
        let bundle_id = dict_string(info, kSecCodeInfoIdentifier);
        CFRelease(info as CFTypeRef);
        CodeSignature { team_id, bundle_id }
    }
}

/// Read a CFString value out of a CFDictionary by CFString key. Value is get-rule (owned by
/// the dict); converted to an owned String immediately.
unsafe fn dict_string(dict: CFDictionaryRef, key: CFStringRef) -> Option<String> {
    let v = CFDictionaryGetValue(dict, key as *const c_void);
    if v.is_null() {
        return None;
    }
    let s = CFString::wrap_under_get_rule(v as CFStringRef);
    Some(s.to_string())
}
