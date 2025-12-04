import { invoke } from '@tauri-apps/api/core'

export async function ping(value: string): Promise<string | null> {
  return await invoke<{value?: string}>('plugin:secure-element|ping', {
    payload: {
      value,
    },
  }).then((r) => (r.value ? r.value : null));
}

export async function generateSecureKey(keySize?: number): Promise<string | null> {
  return await invoke<{key?: string}>('plugin:secure-element|generate_secure_key', {
    payload: {
      keySize,
    },
  }).then((r) => (r.key ? r.key : null));
}

export async function signWithKey(data: string): Promise<Uint8Array> {
  // Convert string to byte array
  const encoder = new TextEncoder();
  const dataBytes = encoder.encode(data);
  
  return await invoke<{signature: number[]}>('plugin:secure-element|sign_with_key', {
    payload: {
      data: Array.from(dataBytes),
    },
  }).then((r) => new Uint8Array(r.signature));
}
