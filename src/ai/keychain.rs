use crate::error::VoxError;
use serde::{Deserialize, Serialize};
use std::io;

const KEYRING_SERVICE: &str = "com.voxshell.desktop";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ApiProvider {
    Gemini,
    OpenAi,
    Deepgram,
}

impl ApiProvider {
    pub fn account_key(&self) -> &'static str {
        match self {
            ApiProvider::Gemini => "gemini_api_key",
            ApiProvider::OpenAi => "openai_api_key",
            ApiProvider::Deepgram => "deepgram_api_key",
        }
    }
}

/// Saves an API key strictly inside the OS Credential Manager (Windows Credential Manager / Linux Secret Service).
pub fn store_api_key(provider: ApiProvider, secret_key: &str) -> Result<(), VoxError> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, provider.account_key())
        .map_err(|e| VoxError::Io(io::Error::new(io::ErrorKind::Other, e.to_string())))?;
    entry
        .set_password(secret_key.trim())
        .map_err(|e| VoxError::Io(io::Error::new(io::ErrorKind::Other, e.to_string())))?;
    Ok(())
}

/// Retrieves an API key from the OS Credential Manager.
pub fn load_api_key(provider: ApiProvider) -> Result<Option<String>, VoxError> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, provider.account_key())
        .map_err(|e| VoxError::Io(io::Error::new(io::ErrorKind::Other, e.to_string())))?;
    match entry.get_password() {
        Ok(secret) if !secret.trim().is_empty() => Ok(Some(secret)),
        Ok(_) | Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(VoxError::Io(io::Error::new(
            io::ErrorKind::Other,
            e.to_string(),
        ))),
    }
}
