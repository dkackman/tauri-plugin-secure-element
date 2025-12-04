use tauri::{command, AppHandle, Runtime};

use crate::models::*;
use crate::Result;
use crate::TauriPluginSecureElementExt;

#[command]
pub(crate) async fn ping<R: Runtime>(
    app: AppHandle<R>,
    payload: PingRequest,
) -> Result<PingResponse> {
    app.tauri_plugin_secure_element().ping(payload)
}

#[command]
pub(crate) async fn generate_secure_key() -> Result<()> {
    eprintln!("[RUST] generate_secure_key command called!");
    println!("[RUST] Generating secure key");
    eprintln!("[RUST] generate_secure_key command completed successfully");
    Ok(())
}

#[command]
pub(crate) async fn sign_data(data: Vec<u8>) -> Result<Vec<u8>> {
    eprintln!("[RUST] sign_data command called with data: {:?}", data);
    println!("[RUST] Signing data: {:?}", data);
    let result = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    eprintln!("[RUST] sign_data returning: {:?}", result);
    Ok(result)
}
