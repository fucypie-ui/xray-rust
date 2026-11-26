use super::protocol::CipherType;

pub fn is_valid_password(cipher: CipherType, password: &str) -> bool {
    cipher != CipherType::None && !password.is_empty()
}

pub struct MethodValidator;

impl MethodValidator {
    pub fn is_supported(method: &str) -> bool { super::runtime::method(method).is_ok() }
    pub fn validate(method: &str, password: &str) -> crate::common::errors::Result<()> {
        super::runtime::account(method, password).map(|_| ())
    }
}
