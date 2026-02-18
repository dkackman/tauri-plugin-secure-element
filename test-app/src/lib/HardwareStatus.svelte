<script lang="ts">
  import type { SecureElementBacking } from "tauri-plugin-secure-element-api";

  let {
    strongest,
    emulated,
    canEnforceBiometricOnly,
    error,
  }: {
    strongest: SecureElementBacking | null;
    emulated: boolean | null;
    canEnforceBiometricOnly: boolean | null;
    error: string;
  } = $props();
</script>

<div class="d-flex flex-wrap gap-2">
  {#if error}
    <span class="badge bg-danger">Hardware Error</span>
  {:else if strongest !== null}
    {#if emulated}
      <span
        class="badge bg-danger"
        title="Virtual/emulated (vTPM, Simulator, Emulator)">Emulated</span
      >
    {/if}
    <span
      class="badge {strongest === 'discrete'
        ? 'bg-success'
        : strongest === 'integrated'
          ? 'bg-success'
          : strongest === 'firmware'
            ? 'bg-warning text-dark'
            : 'bg-secondary'}"
      title={strongest === "discrete"
        ? "Discrete security chip (TPM, T2, StrongBox)"
        : strongest === "integrated"
          ? "On-die security core (Secure Enclave, TEE)"
          : strongest === "firmware"
            ? "Firmware-backed (fTPM)"
            : "No hardware security"}
    >
      {strongest.charAt(0).toUpperCase() + strongest.slice(1)}
    </span>
    {#if canEnforceBiometricOnly}
      <span
        class="badge bg-info"
        title="Biometric-only authentication supported">Bio-Only</span
      >
    {/if}
  {:else}
    <span class="badge bg-secondary">Checking...</span>
  {/if}
</div>
