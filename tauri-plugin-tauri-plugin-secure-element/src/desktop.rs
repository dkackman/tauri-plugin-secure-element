use serde::de::DeserializeOwned;
use tauri::{plugin::PluginApi, AppHandle, Runtime};

use crate::models::*;

pub fn init<R: Runtime, C: DeserializeOwned>(
  app: &AppHandle<R>,
  _api: PluginApi<R, C>,
) -> crate::Result<TauriPluginSecureElement<R>> {
  Ok(TauriPluginSecureElement(app.clone()))
}

/// Access to the tauri-plugin-secure-element APIs.
pub struct TauriPluginSecureElement<R: Runtime>(AppHandle<R>);

impl<R: Runtime> TauriPluginSecureElement<R> {
  pub fn ping(&self, payload: PingRequest) -> crate::Result<PingResponse> {
    Ok(PingResponse {
      value: payload.value,
    })
  }
}
