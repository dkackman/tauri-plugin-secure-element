use tauri::{
    plugin::{Builder, TauriPlugin},
    Manager, Runtime,
};

pub use models::*;

#[cfg(desktop)]
mod desktop;
#[cfg(mobile)]
mod mobile;

mod commands;
mod error;
mod models;

pub use error::{Error, Result};

#[cfg(desktop)]
use desktop::TauriPluginSecureElement;
#[cfg(mobile)]
use mobile::TauriPluginSecureElement;

/// Extensions to [`tauri::App`], [`tauri::AppHandle`] and [`tauri::Window`] to access the tauri-plugin-secure-element APIs.
pub trait TauriPluginSecureElementExt<R: Runtime> {
    fn tauri_plugin_secure_element(&self) -> &TauriPluginSecureElement<R>;
}

impl<R: Runtime, T: Manager<R>> crate::TauriPluginSecureElementExt<R> for T {
    fn tauri_plugin_secure_element(&self) -> &TauriPluginSecureElement<R> {
        self.state::<TauriPluginSecureElement<R>>().inner()
    }
}

/// Initializes the plugin.
pub fn init<R: Runtime>() -> TauriPlugin<R> {
    eprintln!("[PLUGIN] Initializing tauri-plugin-secure-element...");
    eprintln!("[PLUGIN] Registering commands: ping, generate_secure_key, sign_data");
    Builder::new("tauri-plugin-secure-element")
        .invoke_handler(tauri::generate_handler![
            commands::ping,
            commands::generate_secure_key,
            commands::sign_data,
        ])
        .setup(|app, api| {
            eprintln!("[PLUGIN] Setup callback called");
            #[cfg(mobile)]
            let tauri_plugin_secure_element = mobile::init(app, api)?;
            #[cfg(desktop)]
            let tauri_plugin_secure_element = desktop::init(app, api)?;
            app.manage(tauri_plugin_secure_element);
            eprintln!("[PLUGIN] Plugin setup completed successfully");
            Ok(())
        })
        .build()
}
