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

export type HardwareBacking =
  | "secureEnclave"
  | "strongBox"
  | "tee"
  | "ngc"
  | "tpm";

export interface GenerateSecureKeyResult {
  publicKey: string;
  keyName: string;
  /** The type of hardware backing used for this key */
  hardwareBacking: HardwareBacking;
}

export async function generateSecureKey(
  keyName: string,
  authMode: AuthenticationMode = "pinOrBiometric"
): Promise<GenerateSecureKeyResult> {
  return await invoke<GenerateSecureKeyResult>(
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
  data: Uint8Array
): Promise<Uint8Array> {
  return await invoke<{ signature: number[] }>(
    "plugin:secure-element|sign_with_key",
    {
      payload: {
        keyName,
        data: Array.from(data),
      },
    }
  ).then((r) => new Uint8Array(r.signature));
}

/**
 * Delete a key by name or by public key.
 * At least one of keyName or publicKey must be provided.
 */
export async function deleteKey(
  keyName?: string,
  publicKey?: string
): Promise<boolean> {
  return await invoke<{ success: boolean }>(
    "plugin:secure-element|delete_key",
    {
      payload: {
        keyName: keyName || null,
        publicKey: publicKey || null,
      },
    }
  ).then((r) => r.success);
}

export interface SecureElementSupport {
  secureElementSupported: boolean;
  teeSupported: boolean;
  canEnforceBiometricOnly: boolean;
}

export async function checkSecureElementSupport(): Promise<SecureElementSupport> {
  const result = await invoke<SecureElementSupport>(
    "plugin:secure-element|check_secure_element_support"
  );
  return result;
}
