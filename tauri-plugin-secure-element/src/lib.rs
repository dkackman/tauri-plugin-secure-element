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
mod validation;

pub use error::{Error, Result};

#[cfg(desktop)]
use desktop::SecureElement;
#[cfg(mobile)]
use mobile::SecureElement;

// Provide a stub SecureElement for when neither desktop nor mobile is configured
// This allows the code to compile during cargo package
#[cfg(not(any(desktop, mobile)))]
mod stub {
    use tauri::{AppHandle, Runtime};
    use crate::models::*;
    use crate::Result;
    
    pub struct SecureElement<R: Runtime>(AppHandle<R>);
    
    impl<R: Runtime> SecureElement<R> {
        pub fn new(_app: AppHandle<R>) -> Self {
            Self(_app)
        }
        
        pub fn ping(&self, payload: PingRequest) -> Result<PingResponse> {
            Ok(PingResponse { value: payload.value })
        }
        
        pub fn generate_secure_key(&self, _payload: GenerateSecureKeyRequest) -> Result<GenerateSecureKeyResponse> {
            Err(crate::Error::Io(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "Secure element not available - compilation stub",
            )))
        }
        
        pub fn list_keys(&self, _payload: ListKeysRequest) -> Result<ListKeysResponse> {
            Err(crate::Error::Io(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "Secure element not available - compilation stub",
            )))
        }
        
        pub fn sign_with_key(&self, _payload: SignWithKeyRequest) -> Result<SignWithKeyResponse> {
            Err(crate::Error::Io(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "Secure element not available - compilation stub",
            )))
        }
        
        pub fn delete_key(&self, _payload: DeleteKeyRequest) -> Result<DeleteKeyResponse> {
            Err(crate::Error::Io(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "Secure element not available - compilation stub",
            )))
        }
        
        pub fn check_secure_element_support(&self) -> Result<CheckSecureElementSupportResponse> {
            Err(crate::Error::Io(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "Secure element not available - compilation stub",
            )))
        }
    }
}

#[cfg(not(any(desktop, mobile)))]
use stub::SecureElement;

/// Extensions to [`tauri::App`], [`tauri::AppHandle`] and [`tauri::Window`] to access the secure-element APIs.
pub trait SecureElementExt<R: Runtime> {
    fn secure_element(&self) -> &SecureElement<R>;
}

#[cfg(any(desktop, mobile))]
impl<R: Runtime, T: Manager<R>> crate::SecureElementExt<R> for T {
    fn secure_element(&self) -> &SecureElement<R> {
        self.state::<SecureElement<R>>().inner()
    }
}

#[cfg(not(any(desktop, mobile)))]
impl<R: Runtime, T: Manager<R>> crate::SecureElementExt<R> for T {
    fn secure_element(&self) -> &SecureElement<R> {
        // This should never be called during actual use, only for compilation
        panic!("SecureElement is not available - this is a compilation stub")
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
            #[cfg(mobile)]
            {
                let secure_element = mobile::init(app, api)?;
                app.manage(secure_element);
            }
            #[cfg(desktop)]
            {
                let secure_element = desktop::init(app, api)?;
                app.manage(secure_element);
            }
            #[cfg(not(any(desktop, mobile)))]
            {
                // Stub for compilation during cargo package
                let _ = api;
                let secure_element = SecureElement::new(app.clone());
                app.manage(secure_element);
            }
            Ok(())
        })
        .build()
}
