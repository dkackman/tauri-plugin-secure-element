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

/**
 * Controls whether the secure element key requires user authentication before signing.
 *
 * - `"pinOrBiometric"` — requires Windows Hello (PIN or biometric) on Windows, or device
 *   credential on iOS/Android. Recommended for most use cases.
 * - `"biometricOnly"` — biometric-only (not supported on Windows; use `"pinOrBiometric"`).
 * - `"none"` — no authentication prompt required at signing time. On Windows this creates
 *   a Platform Crypto Provider (TPM) key that any process running as the same user can use
 *   silently, given knowledge of the key name. Choose this only when silent background
 *   signing is an intentional requirement and you accept that user-level process isolation
 *   is the only boundary protecting the key.
 */
export type AuthenticationMode = "none" | "pinOrBiometric" | "biometricOnly";

export interface GenerateSecureKeyResult {
  publicKey: string;
  keyName: string;
  /** The actual backing tier this key ended up in, as reported by the platform
   * after creation — not the tier that was requested. On Android this may be
   * `"integrated"` (TEE) even on a device that supports `"discrete"` (StrongBox)
   * if StrongBox creation failed, and it may be `"software"` on an emulator or a
   * device with no TEE. Key generation does not fail on an unbacked device, so
   * this field is the only thing that tells you what you actually got: check it
   * with {@link isHardwareBacked} to enforce a minimum tier. */
  backing: SecureElementBacking;
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
      keyName: keyName ?? null,
      publicKey: publicKey ?? null,
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
        keyName: keyName ?? null,
        publicKey: publicKey ?? null,
      },
    }
  ).then((r) => r.success);
}

/**
 * Secure element hardware backing tiers.
 * Ordered weakest → strongest: none < software < firmware < integrated < discrete
 *
 * `"software"` means the key is real and fully functional, but protected only by
 * the OS rather than by hardware — the case on the Android emulator and on devices
 * with no TEE. It is reported rather than refused so that behaviour is consistent
 * across platforms (the iOS Simulator likewise serves keys from a software Secure
 * Enclave). Callers that require hardware protection must check for it; see
 * {@link isHardwareBacked}.
 */
export type SecureElementBacking =
  "none" | "software" | "firmware" | "integrated" | "discrete";

/**
 * Whether a backing tier is protected by hardware rather than by the OS alone.
 *
 * Use this to gate security-sensitive flows instead of comparing tier strings by
 * hand:
 *
 * ```ts
 * const key = await generateSecureKey(name, "pinOrBiometric");
 * if (!isHardwareBacked(key.backing)) {
 *   throw new Error("This operation requires a hardware-backed key.");
 * }
 * ```
 */
export function isHardwareBacked(backing: SecureElementBacking): boolean {
  return (
    backing === "firmware" || backing === "integrated" || backing === "discrete"
  );
}

/**
 * Secure element capabilities for the current device.
 */
export interface SecureElementCapabilities {
  /** A discrete physical security chip is available (e.g. discrete TPM, T2, StrongBox) */
  discrete: boolean;
  /** An on-die isolated security core is available (e.g. Secure Enclave, TrustZone/TEE) */
  integrated: boolean;
  /** Firmware-backed security is available but no dedicated secure processor (e.g. fTPM) */
  firmware: boolean;
  /** The security is emulated/virtual (e.g. vTPM in VM, iOS Simulator, Android Emulator) */
  emulated: boolean;
  /** The strongest tier available on this device */
  strongest: SecureElementBacking;
  /** Whether biometric-only authentication can be enforced at the key level */
  canEnforceBiometricOnly: boolean;
}

export async function checkSecureElementSupport(): Promise<SecureElementCapabilities> {
  const result = await invoke<SecureElementCapabilities>(
    "plugin:secure-element|check_secure_element_support"
  );
  return result;
}
