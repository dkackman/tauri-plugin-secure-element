import { invoke } from "@tauri-apps/api/core";

export interface KeyInfo {
  keyName: string;
  publicKey: string;
}

export async function ping(value: string): Promise<string | null> {
  return await invoke<{ value?: string }>("plugin:secure-element|ping", {
    payload: {
      value,
    },
  }).then((r) => (r.value ? r.value : null));
}

export async function generateSecureKey(
  keyName: string
): Promise<{ publicKey: string; keyName: string }> {
  return await invoke<{ publicKey: string; keyName: string }>(
    "plugin:secure-element|generate_secure_key",
    {
      payload: {
        keyName,
      },
    }
  );
}

export async function listKeys(
  keyName?: string,
  publicKey?: string
): Promise<KeyInfo[]> {
  return await invoke<{ keys: KeyInfo[] }>("plugin:secure-element|list_keys", {
    payload: {
      keyName: keyName || null,
      publicKey: publicKey || null,
    },
  }).then((r) => r.keys);
}

export async function signWithKey(
  keyName: string,
  data: string
): Promise<Uint8Array> {
  // Convert string to byte array
  const encoder = new TextEncoder();
  const dataBytes = encoder.encode(data);

  return await invoke<{ signature: number[] }>(
    "plugin:secure-element|sign_with_key",
    {
      payload: {
        keyName,
        data: Array.from(dataBytes),
      },
    }
  ).then((r) => new Uint8Array(r.signature));
}

export async function deleteKey(keyName: string): Promise<boolean> {
  return await invoke<{ success: boolean }>(
    "plugin:secure-element|delete_key",
    {
      payload: {
        keyName,
      },
    }
  ).then((r) => r.success);
}
