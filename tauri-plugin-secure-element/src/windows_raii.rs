use std::ops::{Deref, DerefMut};
use windows::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::Cryptography::{
    NCryptFreeBuffer, NCryptFreeObject, NCryptKeyName, NCRYPT_KEY_HANDLE, NCRYPT_PROV_HANDLE,
};

pub struct HLocalGuard(HLOCAL);

impl HLocalGuard {
    /// Creates a new guard with an invalid handle
    /// The handle should be set by a Windows API call that allocates memory requiring LocalFree
    pub fn new() -> Self {
        Self(HLOCAL::default())
    }

    /// Sets the handle from a PWSTR pointer
    /// This is used when a Windows API returns a PWSTR that needs to be freed with LocalFree
    pub fn set_from_pwstr(&mut self, pwstr: windows::core::PWSTR) {
        self.0 = HLOCAL(pwstr.as_ptr() as *mut _);
    }
}

impl Drop for HLocalGuard {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = LocalFree(self.0);
            }
        }
    }
}

pub struct WindowsHandleGuard(pub HANDLE);

impl WindowsHandleGuard {
    /// Creates a new guard with an invalid handle
    /// The handle should be initialized by a Windows API call that takes &mut HANDLE
    pub fn new() -> Self {
        Self(HANDLE::default())
    }
}

impl Deref for WindowsHandleGuard {
    type Target = HANDLE;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for WindowsHandleGuard {
    fn deref_mut(&mut self) -> &mut HANDLE {
        &mut self.0
    }
}

impl Drop for WindowsHandleGuard {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}
/// RAII wrapper for NCRYPT_PROV_HANDLE
pub struct ProviderHandle(pub NCRYPT_PROV_HANDLE);

impl Deref for ProviderHandle {
    type Target = NCRYPT_PROV_HANDLE;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for ProviderHandle {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Drop for ProviderHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = NCryptFreeObject(self.0);
            }
        }
    }
}

/// RAII wrapper for NCRYPT_KEY_HANDLE
pub struct KeyHandle(pub NCRYPT_KEY_HANDLE);

impl KeyHandle {
    /// Takes ownership of the inner handle, preventing Drop from being called
    /// This is useful when another API takes ownership of the handle (e.g., NCryptDeleteKey)
    pub fn take(self) -> NCRYPT_KEY_HANDLE {
        let handle = self.0;
        std::mem::forget(self);
        handle
    }
}

impl Deref for KeyHandle {
    type Target = NCRYPT_KEY_HANDLE;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for KeyHandle {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Drop for KeyHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = NCryptFreeObject(self.0);
            }
        }
    }
}

/// RAII guard for NCrypt enumeration state to prevent memory leaks
pub struct EnumStateGuard(*mut std::ffi::c_void);

impl EnumStateGuard {
    pub fn new() -> Self {
        Self(std::ptr::null_mut())
    }

    pub fn as_mut_ptr(&mut self) -> *mut *mut std::ffi::c_void {
        &mut self.0
    }
}

impl Drop for EnumStateGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                let _ = NCryptFreeBuffer(self.0);
            }
        }
    }
}

/// RAII guard for NCrypt key name buffer to prevent memory leaks
pub struct KeyNameBufferGuard(*mut NCryptKeyName);

impl KeyNameBufferGuard {
    /// Creates a new guard from a key name pointer
    /// The pointer should be non-null and allocated by NCryptEnumKeys
    pub fn new(ptr: *mut NCryptKeyName) -> Self {
        Self(ptr)
    }

    /// Gets a reference to the key name structure
    /// # Safety
    /// Must be called from an unsafe context. The pointer must be valid and non-null.
    pub fn as_ref(&self) -> &NCryptKeyName {
        unsafe { &*self.0 }
    }
}

impl Drop for KeyNameBufferGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                let _ = NCryptFreeBuffer(self.0 as *mut std::ffi::c_void);
            }
        }
    }
}
