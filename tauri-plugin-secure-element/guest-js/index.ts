import { invoke } from "@tauri-apps/api/core";

/**
 * Machine-readable classification of a failure.
 *
 * Every rejection from this plugin carries one. Branch on the code, never on
 * the message: messages are deliberately generic in release builds (so they
 * cannot leak key names or OS status values) and their wording is not part of
 * the API.
 *
 * - `"userCancelled"` — the user dismissed the authentication prompt, or the OS
 *   dismissed it for them. Expected and benign; usually the right response is
 *   to do nothing rather than show an error.
 * - `"authFailed"` — authentication ran and was rejected (wrong PIN,
 *   unrecognized biometric, biometry locked out). Retrying is reasonable.
 * - `"keyInvalidated"` — the key exists but can never be used again, because
 *   the enrolled biometric set changed after it was created. There is no
 *   recovery: delete the key and generate a new one, then re-enroll the new
 *   public key wherever the old one was registered. Only Android reports this
 *   precisely; Apple platforms cannot distinguish it from `"authFailed"`.
 * - `"keyNotFound"` — no key matched the given name or public key.
 * - `"keyAlreadyExists"` — a key with that name already exists.
 * - `"keyNotAccessible"` — the key exists but is not usable right now, usually
 *   because the device is locked. Transient, unlike `"keyInvalidated"`.
 * - `"deviceNotSecure"` — no passcode/PIN is set, or no biometric is enrolled,
 *   and the requested mode needs one. The user can fix this and retry.
 * - `"unsupported"` — not available on this platform, OS version, or hardware
 *   (e.g. `"biometricOnly"` on Windows). Retrying will not help.
 * - `"validation"` — bad arguments; a bug in the calling code.
 * - `"internal"` — anything else, and the correct fallback for a code this
 *   version of the bindings does not recognize.
 */
export type SecureElementErrorCode =
  | "userCancelled"
  | "authFailed"
  | "keyInvalidated"
  | "keyNotFound"
  | "keyAlreadyExists"
  | "keyNotAccessible"
  | "deviceNotSecure"
  | "unsupported"
  | "validation"
  | "internal";

/**
 * The error every function in this module rejects with.
 *
 * ```ts
 * try {
 *   await signWithKey("my-key", data);
 * } catch (e) {
 *   if (isSecureElementError(e)) {
 *     switch (e.code) {
 *       case "userCancelled":
 *         return; // not an error — the user declined
 *       case "keyInvalidated":
 *         await deleteKey("my-key");
 *         return reenroll();
 *       default:
 *         showError(e.message);
 *     }
 *   }
 * }
 * ```
 */
export class SecureElementError extends Error {
  readonly code: SecureElementErrorCode;

  constructor(code: SecureElementErrorCode, message: string) {
    super(message);
    this.name = "SecureElementError";
    this.code = code;
    // Restores the prototype chain when this file is down-levelled to ES5,
    // where `extends Error` otherwise breaks `instanceof`.
    Object.setPrototypeOf(this, SecureElementError.prototype);
  }
}

/** Type guard for {@link SecureElementError}. */
export function isSecureElementError(
  error: unknown
): error is SecureElementError {
  return error instanceof SecureElementError;
}

/**
 * Every known code, used to recognize codes rather than trust them blindly.
 *
 * A value arriving from the plugin that is not in this set means the Rust core
 * is newer than these bindings. That collapses to `"internal"`, which is the
 * documented fallback, instead of being surfaced as a code the caller's
 * `switch` cannot possibly handle.
 */
const KNOWN_ERROR_CODES = new Set<string>([
  "userCancelled",
  "authFailed",
  "keyInvalidated",
  "keyNotFound",
  "keyAlreadyExists",
  "keyNotAccessible",
  "deviceNotSecure",
  "unsupported",
  "validation",
  "internal",
]);

/**
 * Normalizes whatever `invoke` rejected with into a {@link SecureElementError}.
 *
 * The plugin's own errors arrive as `{code, message}`. Anything else — a
 * capability denial raised by Tauri itself, a serialization fault, a thrown
 * `Error` — has no code of its own and becomes `"internal"` with its text
 * preserved.
 */
function toSecureElementError(error: unknown): SecureElementError {
  if (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    typeof (error as { code: unknown }).code === "string"
  ) {
    const { code, message } = error as { code: string; message?: unknown };
    return new SecureElementError(
      KNOWN_ERROR_CODES.has(code)
        ? (code as SecureElementErrorCode)
        : "internal",
      typeof message === "string" && message.length > 0
        ? message
        : "Secure element operation failed"
    );
  }

  if (error instanceof Error) {
    return new SecureElementError("internal", error.message);
  }

  return new SecureElementError(
    "internal",
    typeof error === "string" ? error : "Secure element operation failed"
  );
}

/**
 * `invoke`, with every rejection normalized to a {@link SecureElementError}.
 *
 * Every command goes through this so callers never have to deal with two error
 * shapes depending on whether the failure came from the plugin or from Tauri's
 * own IPC layer.
 */
async function invokeSecureElement<T>(
  command: string,
  args?: Record<string, unknown>
): Promise<T> {
  try {
    return await invoke<T>(command, args);
  } catch (error) {
    throw toSecureElementError(error);
  }
}

/**
 * Information about a key.
 *
 * This deliberately carries no authentication mode or provider, and should not
 * be given one. Windows and Android can attest it from the OS at listing time,
 * but Apple cannot recover it at all — the mode survives only inside a
 * `SecAccessControl`, which exposes no accessor for its flags — so the field
 * would be OS-attested on some platforms and self-reported on others, with no
 * way for a caller to tell which one they hold. See the `KeyInfo` doc comment
 * in `src/models.rs` for the full rationale.
 *
 * If you need a key's auth mode, record it yourself when you call
 * `generateSecureKey`; that is reliable on every platform.
 */
export interface KeyInfo {
  keyName: string;
  publicKey: string;
}

export async function ping(value: string): Promise<string | null> {
  return await invokeSecureElement<{ value?: string }>(
    "plugin:secure-element|ping",
    {
      payload: {
        value,
      },
    }
  ).then((r) => (r.value ? r.value : null));
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
  return await invokeSecureElement<GenerateSecureKeyResult>(
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
  return await invokeSecureElement<{ keys: KeyInfo[] }>(
    "plugin:secure-element|list_keys",
    {
      payload: {
        keyName: keyName ?? null,
        publicKey: publicKey ?? null,
      },
    }
  ).then((r) => r.keys);
}

/**
 * Encodes bytes as a base64 string. Chunked to stay well under JS engines'
 * argument-count limits for `String.fromCharCode(...)` on large inputs.
 */
function bytesToBase64(bytes: Uint8Array): string {
  const chunkSize = 0x8000;
  let binary = "";
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }
  return btoa(binary);
}

/** Decodes a base64 string to bytes (a DER signature, so tens of bytes — no chunking needed). */
function base64ToBytes(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Signs data with a key held in the secure element.
 *
 * For a key created with `"pinOrBiometric"` or `"biometricOnly"`, this raises
 * an authentication prompt: Face ID / Touch ID / passcode on Apple platforms,
 * BiometricPrompt on Android, Windows Hello on Windows.
 *
 * @param reason What the user is being asked to approve, shown in that prompt.
 * The plugin cannot show them the bytes being signed — those are opaque and
 * meaningless to a human — so this string is the only thing distinguishing one
 * signature request from another at the moment of consent:
 *
 * ```ts
 * await signWithKey("my-key", tx, `Approve transfer of ${amount} to ${payee}`);
 * ```
 *
 * Omitted, each platform falls back to a generic message. Limited to 200
 * characters, and rejected if blank or containing control characters.
 *
 * This is a hint, not a guarantee: the OS owns the prompt, and no platform
 * binds the displayed string to the signed bytes cryptographically. Always
 * derive it from the same data being signed — a mismatch means the user
 * consented to something other than what they signed.
 */
export async function signWithKey(
  keyName: string,
  data: Uint8Array,
  reason?: string
): Promise<Uint8Array> {
  return await invokeSecureElement<{ signature: string }>(
    "plugin:secure-element|sign_with_key",
    {
      payload: {
        keyName,
        data: bytesToBase64(data),
        reason: reason ?? null,
      },
    }
  ).then((r) => base64ToBytes(r.signature));
}

/** Options for {@link deleteKey}. */
export interface DeleteKeyOptions {
  /**
   * Require the user to authenticate before the key is destroyed.
   *
   * No platform enforces this by itself: `SecItemDelete`, `NCryptDeleteKey` and
   * `KeyStore.deleteEntry` all succeed against keys created with
   * `"pinOrBiometric"` or `"biometricOnly"`, without any prompt. So anything
   * that can reach this command — including injected webview JavaScript holding
   * the capability — can otherwise destroy every key the app owns. Setting this
   * adds a device-owner check (biometric or device passcode/PIN) that the
   * plugin performs itself.
   *
   * The prompt appears *before* the key is looked up, so deleting a key that
   * does not exist still prompts. That is deliberate: prompting only for keys
   * that exist would let a caller with deletion rights probe for key names.
   *
   * Rejects with `"userCancelled"` if the user declines — the key is left
   * intact.
   */
  requireAuth?: boolean;
  /**
   * Message shown in that prompt. Ignored unless `requireAuth` is set; falls
   * back to a generic message. Same limits as `signWithKey`'s reason.
   */
  reason?: string;
}

/**
 * Delete a key by name or by public key.
 * Exactly one of keyName or publicKey must be provided.
 *
 * Deleting a key that does not exist succeeds — deletion is idempotent.
 *
 * ```ts
 * await deleteKey("my-key", undefined, {
 *   requireAuth: true,
 *   reason: "Confirm removal of your signing key",
 * });
 * ```
 */
export async function deleteKey(
  keyName?: string,
  publicKey?: string,
  options?: DeleteKeyOptions
): Promise<boolean> {
  return await invokeSecureElement<{ success: boolean }>(
    "plugin:secure-element|delete_key",
    {
      payload: {
        keyName: keyName ?? null,
        publicKey: publicKey ?? null,
        requireAuth: options?.requireAuth ?? false,
        reason: options?.reason ?? null,
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
  /**
   * The security is emulated/virtual (e.g. vTPM in VM, iOS Simulator, Android Emulator).
   * Authoritative on iOS/macOS (compile-time simulator check) and Windows (TPM interface
   * type reported by the TBS API). On Android this is a build-fingerprint heuristic —
   * there is no OS API that reports emulation reliably, so it can be spoofed by a custom
   * ROM/rooted device and can misfire on real hardware with unusual build properties.
   * Treat it as best-effort on Android.
   */
  emulated: boolean;
  /** The strongest tier available on this device */
  strongest: SecureElementBacking;
  /**
   * Whether biometric-only authentication can be enforced at the key level right now.
   * Reflects live enrollment on every platform that supports the mode (iOS/macOS via
   * LAContext, Android via BiometricManager as of the API 30+ check) — re-check before
   * each `generateSecureKey(.., "biometricOnly")` call rather than caching the result.
   */
  canEnforceBiometricOnly: boolean;
}

export async function checkSecureElementSupport(): Promise<SecureElementCapabilities> {
  const result = await invokeSecureElement<SecureElementCapabilities>(
    "plugin:secure-element|check_secure_element_support"
  );
  return result;
}
