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
use core_foundation_sys::base::{CFRelease, CFTypeRef};
use core_foundation_sys::dictionary::{CFDictionaryGetValue, CFDictionaryRef};
use core_foundation_sys::string::CFStringRef;

type SecCodeRef = *const c_void;

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
    static kSecGuestAttributePid: CFStringRef;
    static kSecCodeInfoTeamIdentifier: CFStringRef;
    static kSecCodeInfoIdentifier: CFStringRef;
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
