use std::ops::{Deref, DerefMut};
use windows::Win32::Foundation::{LocalFree, HLOCAL};
use windows::Win32::Security::Cryptography::{
    NCryptFreeBuffer, NCryptFreeObject, NCryptKeyName, NCRYPT_KEY_HANDLE, NCRYPT_PROV_HANDLE,
};

/// Macro to define RAII wrapper types with automatic cleanup
macro_rules! define_raii_handle {
    // Basic version: pub struct with Drop
    ($(#[$meta:meta])* $vis:vis $name:ident($field_vis:vis $handle_type:ty), $cleanup_fn:path, $check:ident) => {
        $(#[$meta])*
        $vis struct $name($field_vis $handle_type);

        impl Drop for $name {
            fn drop(&mut self) {
                if !self.0.$check() {
                    unsafe {
                        let _ = $cleanup_fn(self.0);
                    }
                }
            }
        }
    };

    // With .into() conversion for cleanup (when cleanup function expects a convertible type)
    ($(#[$meta:meta])* $vis:vis $name:ident($field_vis:vis $handle_type:ty), $cleanup_fn:path, $check:ident, into) => {
        $(#[$meta])*
        $vis struct $name($field_vis $handle_type);

        impl Drop for $name {
            fn drop(&mut self) {
                if !self.0.$check() {
                    unsafe {
                        let _ = $cleanup_fn(self.0.into());
                    }
                }
            }
        }
    };

    // With Deref/DerefMut for transparent handle access
    ($(#[$meta:meta])* $vis:vis $name:ident($field_vis:vis $handle_type:ty), $cleanup_fn:path, $check:ident, deref) => {
        define_raii_handle!($(#[$meta])* $vis $name($field_vis $handle_type), $cleanup_fn, $check);

        impl Deref for $name {
            type Target = $handle_type;
            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl DerefMut for $name {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.0
            }
        }
    };

    // With .into() conversion + Deref/DerefMut
    ($(#[$meta:meta])* $vis:vis $name:ident($field_vis:vis $handle_type:ty), $cleanup_fn:path, $check:ident, into, deref) => {
        define_raii_handle!($(#[$meta])* $vis $name($field_vis $handle_type), $cleanup_fn, $check, into);

        impl Deref for $name {
            type Target = $handle_type;
            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl DerefMut for $name {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.0
            }
        }
    };

    // With cast for cleanup (needed when cleanup function expects different type)
    ($(#[$meta:meta])* $vis:vis $name:ident($field_vis:vis $handle_type:ty), $cleanup_fn:path, $check:ident, cast: $cast_type:ty) => {
        $(#[$meta])*
        $vis struct $name($field_vis $handle_type);

        impl Drop for $name {
            fn drop(&mut self) {
                if !self.0.$check() {
                    unsafe {
                        let _ = $cleanup_fn(self.0 as $cast_type);
                    }
                }
            }
        }
    };
}

define_raii_handle!(pub HLocalGuard(HLOCAL), LocalFree, is_invalid, into);

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

define_raii_handle!(
    /// RAII wrapper for NCRYPT_PROV_HANDLE that automatically calls NCryptFreeObject on drop
    pub ProviderHandle(pub NCRYPT_PROV_HANDLE), NCryptFreeObject, is_invalid, into, deref
);

define_raii_handle!(
    /// RAII wrapper for NCRYPT_KEY_HANDLE that automatically calls NCryptFreeObject on drop
    pub KeyHandle(pub NCRYPT_KEY_HANDLE), NCryptFreeObject, is_invalid, into, deref
);

impl KeyHandle {
    /// Takes ownership of the inner handle, preventing Drop from being called
    /// This is useful when another API takes ownership of the handle (e.g., NCryptDeleteKey)
    pub fn take(self) -> NCRYPT_KEY_HANDLE {
        let handle = self.0;
        std::mem::forget(self);
        handle
    }
}

define_raii_handle!(
    /// RAII guard for NCrypt enumeration state that automatically calls NCryptFreeBuffer on drop
    pub EnumStateGuard(*mut std::ffi::c_void), NCryptFreeBuffer, is_null
);

impl EnumStateGuard {
    pub fn new() -> Self {
        Self(std::ptr::null_mut())
    }

    pub fn as_mut_ptr(&mut self) -> *mut *mut std::ffi::c_void {
        &mut self.0
    }
}

define_raii_handle!(
    /// RAII guard for NCrypt key name buffer that automatically calls NCryptFreeBuffer on drop
    pub KeyNameBufferGuard(*mut NCryptKeyName), NCryptFreeBuffer, is_null, cast: *mut std::ffi::c_void
);

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
