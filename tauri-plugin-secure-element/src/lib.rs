use tauri::{
    plugin::{Builder, TauriPlugin},
    Manager, Runtime,
};

pub use models::*;

#[cfg(all(desktop, not(target_os = "macos")))]
mod desktop;
#[cfg(any(mobile, target_os = "macos"))]
mod mobile;

mod commands;
mod error;
mod models;
mod validation;

pub use error::{Error, Result};

#[cfg(all(desktop, not(target_os = "macos")))]
use desktop::SecureElement;
#[cfg(any(mobile, target_os = "macos"))]
use mobile::SecureElement;

/// Extensions to [`tauri::App`], [`tauri::AppHandle`] and [`tauri::Window`] to access the secure-element APIs.
pub trait SecureElementExt<R: Runtime> {
    fn secure_element(&self) -> &SecureElement<R>;
}

impl<R: Runtime, T: Manager<R>> crate::SecureElementExt<R> for T {
    fn secure_element(&self) -> &SecureElement<R> {
        self.state::<SecureElement<R>>().inner()
    }
}

/// Initializes the plugin.
pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("secure-element")
        .invoke_handler(tauri::generate_handler![
            commands::ping,
            commands::generate_secure_key,
            commands::list_keys,
            commands::sign_with_key,
            commands::delete_key,
            commands::check_secure_element_support
        ])
        .setup(|app, api| {
            #[cfg(any(mobile, target_os = "macos"))]
            let secure_element = mobile::init(app, api)?;
            #[cfg(all(desktop, not(target_os = "macos")))]
            let secure_element = desktop::init(app, api)?;
            app.manage(secure_element);
            Ok(())
        })
        .build()
}
