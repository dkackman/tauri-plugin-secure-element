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

export type AuthenticationMode = "none" | "pinOrBiometric" | "biometricOnly";

export async function generateSecureKey(
  keyName: string,
  authMode: AuthenticationMode = "pinOrBiometric"
): Promise<{ publicKey: string; keyName: string }> {
  return await invoke<{ publicKey: string; keyName: string }>(
    "plugin:secure-element|generate_secure_key",
    {
      payload: {
        keyName,
        authMode,
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
  data: Uint8Array,
  authMode: AuthenticationMode = "pinOrBiometric"
): Promise<Uint8Array> {
  return await invoke<{ signature: number[] }>(
    "plugin:secure-element|sign_with_key",
    {
      payload: {
        keyName,
        data: Array.from(data),
        authMode,
      },
    }
  ).then((r) => new Uint8Array(r.signature));
}

export async function deleteKey(
  keyName: string,
  authMode: AuthenticationMode = "pinOrBiometric"
): Promise<boolean> {
  return await invoke<{ success: boolean }>(
    "plugin:secure-element|delete_key",
    {
      payload: {
        keyName,
        authMode,
      },
    }
  ).then((r) => r.success);
}

export interface SecureElementSupport {
  secureElementSupported: boolean;
  teeSupported: boolean;
}

export async function checkSecureElementSupport(): Promise<SecureElementSupport> {
  const result = await invoke<SecureElementSupport>(
    "plugin:secure-element|check_secure_element_support"
  );
  return result;
}
