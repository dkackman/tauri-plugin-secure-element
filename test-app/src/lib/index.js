// Use Tauri's global API (available in Tauri v2)
const { invoke } = window.__TAURI__.core;

export async function ping(value) {
    return await invoke('plugin:tauri-plugin-secure-element|ping', {
        payload: {
            value,
        },
    }).then((r) => (r.value ? r.value : null));
}

/**
 * Generates a secure key.
 * @returns Promise that resolves when the key is generated
 */
export async function generateSecureKey() {
    return await invoke('plugin:tauri-plugin-secure-element|generate_secure_key');
}

/**
 * Signs data using the secure element.
 * @param data - The data to sign as a Uint8Array
 * @returns Promise that resolves to the signed data as a Uint8Array
 */
export async function signData(data) {
    return await invoke('plugin:tauri-plugin-secure-element|sign_data', {
        data: Array.from(data),
    }).then((result) => new Uint8Array(result));
}

