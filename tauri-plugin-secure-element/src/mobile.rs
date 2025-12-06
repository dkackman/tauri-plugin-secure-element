use serde::de::DeserializeOwned;
use tauri::{
    plugin::{PluginApi, PluginHandle},
    AppHandle, Runtime,
};

use crate::models::*;

#[cfg(target_os = "ios")]
tauri::ios_plugin_binding!(init_plugin_secure_element);

// initializes the Kotlin or Swift plugin classes
pub fn init<R: Runtime, C: DeserializeOwned>(
    _app: &AppHandle<R>,
    api: PluginApi<R, C>,
) -> crate::Result<SecureElement<R>> {
    #[cfg(target_os = "android")]
    let handle =
        api.register_android_plugin("app.tauri.plugin.secureelement", "SecureKeysPlugin")?;
    #[cfg(target_os = "ios")]
    let handle = api.register_ios_plugin(init_plugin_secure_element)?;
    Ok(SecureElement(handle))
}

/// Access to the secure-element APIs.
pub struct SecureElement<R: Runtime>(PluginHandle<R>);

impl<R: Runtime> SecureElement<R> {
    pub fn ping(&self, payload: PingRequest) -> crate::Result<PingResponse> {
        self.0
            .run_mobile_plugin("ping", payload)
            .map_err(Into::into)
    }

    pub fn generate_secure_key(
        &self,
        payload: GenerateSecureKeyRequest,
    ) -> crate::Result<GenerateSecureKeyResponse> {
        self.0
            .run_mobile_plugin("generateSecureKey", payload)
            .map_err(Into::into)
    }

    pub fn list_keys(&self, payload: ListKeysRequest) -> crate::Result<ListKeysResponse> {
        self.0
            .run_mobile_plugin("listKeys", payload)
            .map_err(Into::into)
    }

    pub fn sign_with_key(&self, payload: SignWithKeyRequest) -> crate::Result<SignWithKeyResponse> {
        self.0
            .run_mobile_plugin("signWithKey", payload)
            .map_err(Into::into)
    }

    pub fn delete_key(&self, payload: DeleteKeyRequest) -> crate::Result<DeleteKeyResponse> {
        self.0
            .run_mobile_plugin("deleteKey", payload)
            .map_err(Into::into)
    }

    pub fn check_secure_element_support(&self) -> crate::Result<CheckSecureElementSupportResponse> {
        self.0
            .run_mobile_plugin("checkSecureElementSupport", ())
            .map_err(Into::into)
    }
}
