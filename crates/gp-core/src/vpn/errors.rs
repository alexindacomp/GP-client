//! Error carrying a [`VpnErrorCode`].

use crate::types::{VpnErrorCode, VpnErrorHint};

/// Anything that fails inside a connection attempt. `message` is the technical (English,
/// untranslated) cause that ends up masked in `VpnState.error.detail`; `hint` selects a
/// cause-specific next step instead of the per-code one.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct VpnError {
    pub code: VpnErrorCode,
    pub message: String,
    pub hint: Option<VpnErrorHint>,
}

impl VpnError {
    pub fn new(code: VpnErrorCode, message: impl Into<String>) -> Self {
        VpnError {
            code,
            message: message.into(),
            hint: None,
        }
    }

    #[must_use]
    pub fn with_hint(mut self, hint: VpnErrorHint) -> Self {
        self.hint = Some(hint);
        self
    }
}

/// `isVpnErrorCode`: parses the wire string of a code.
pub fn parse_vpn_error_code(s: &str) -> Option<VpnErrorCode> {
    VpnErrorCode::ALL.into_iter().find(|c| c.as_str() == s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_round_trip_and_unknown_strings_are_rejected() {
        for c in VpnErrorCode::ALL {
            assert_eq!(parse_vpn_error_code(c.as_str()), Some(c));
        }
        assert_eq!(parse_vpn_error_code("bad_value"), None);
        let e = VpnError::new(VpnErrorCode::PrivilegesDenied, "x").with_hint(VpnErrorHint::StopFailed);
        assert_eq!(e.to_string(), "x");
        assert_eq!(e.hint, Some(VpnErrorHint::StopFailed));
    }
}
