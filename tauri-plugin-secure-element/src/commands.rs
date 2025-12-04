use tauri::{command, AppHandle, Runtime};

use crate::models::*;
use crate::Result;
use crate::SecureElementExt;

#[command]
pub(crate) async fn ping<R: Runtime>(
    app: AppHandle<R>,
    payload: PingRequest,
) -> Result<PingResponse> {
    app.secure_element().ping(payload)
}
