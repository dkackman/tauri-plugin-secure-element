<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { Copy } from "lucide-svelte";
  import { signWithKey, type KeyInfo } from "tauri-plugin-secure-element-api";
  import SpinnerButton from "./SpinnerButton.svelte";
  import { copyToClipboard } from "./utils.js";

  let {
    keysList,
    selectedKeyName = $bindable(""),
  }: {
    keysList: KeyInfo[];
    selectedKeyName: string;
  } = $props();

  let messageToSign = $state("");
  let signature = $state<Uint8Array | null>(null);
  let signError = $state("");
  let verifyPublicKey = $state("");
  let verifyResult = $state<boolean | null>(null);
  let verifyError = $state("");
  let isVerifying = $state(false);

  // Clear signing state when the selected key changes
  $effect(() => {
    selectedKeyName;
    signature = null;
    verifyResult = null;
    signError = "";
    verifyError = "";
  });

  function formatSignature(sig: Uint8Array | null): string {
    if (!sig) return "";
    return Array.from(sig)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  function signMessage() {
    if (!selectedKeyName.trim()) {
      signError = "Please select a key";
      return;
    }
    if (!messageToSign.trim()) {
      signError = "Please enter a message to sign";
      return;
    }
    signError = "";
    signature = null;
    verifyResult = null;
    verifyError = "";

    const encoder = new TextEncoder();
    const dataBytes = encoder.encode(messageToSign);
    signWithKey(selectedKeyName.trim(), dataBytes)
      .then((sig) => {
        signature = sig;
        // Auto-populate verify public key from selected key
        const selectedKey = keysList.find((k) => k.keyName === selectedKeyName);
        if (selectedKey) {
          verifyPublicKey = selectedKey.publicKey;
        }
      })
      .catch((err) => {
        signError = err.toString();
      });
  }

  async function verifySignature() {
    if (!signature) {
      verifyError = "No signature to verify";
      return;
    }
    if (!verifyPublicKey.trim()) {
      verifyError = "Please enter the public key";
      return;
    }
    if (!messageToSign.trim()) {
      verifyError = "Message is required";
      return;
    }

    verifyError = "";
    verifyResult = null;
    isVerifying = true;

    try {
      const encoder = new TextEncoder();
      const messageBytes = Array.from(encoder.encode(messageToSign));
      const signatureBytes = Array.from(signature);

      verifyResult = await invoke<boolean>("verify_signature", {
        publicKeyBase64: verifyPublicKey.trim(),
        message: messageBytes,
        signatureDer: signatureBytes,
      });
    } catch (err) {
      verifyError = err instanceof Error ? err.message : String(err);
    } finally {
      isVerifying = false;
    }
  }
</script>

<section class="card h-100">
  <div class="card-header">
    <h2 class="h5 mb-0">Sign & Verify</h2>
  </div>
  <div class="card-body">
    {#if keysList.length === 0}
      <div class="text-center text-muted py-4">
        <p class="mb-0">Create a key first to sign messages</p>
      </div>
    {:else}
      <!-- Key Selection -->
      <div class="mb-3">
        <label for="keySelect" class="form-label small fw-medium">
          Select Key
        </label>
        <select
          id="keySelect"
          bind:value={selectedKeyName}
          class="form-select"
          onchange={() => {
            signature = null;
            verifyResult = null;
          }}
        >
          <option value="">Choose a key...</option>
          {#each keysList as key}
            <option value={key.keyName}>{key.keyName}</option>
          {/each}
        </select>
      </div>

      <!-- Message Input -->
      <div class="mb-3">
        <label for="message" class="form-label small fw-medium">Message</label>
        <textarea
          id="message"
          class="form-control"
          bind:value={messageToSign}
          placeholder="Enter message to sign"
          rows="3"
          disabled={!selectedKeyName}
        ></textarea>
      </div>

      <!-- Sign Button -->
      <button
        onclick={signMessage}
        class="btn btn-success w-100 mb-3"
        disabled={!selectedKeyName || !messageToSign.trim()}
      >
        Sign Message
      </button>

      {#if signError}
        <div class="alert alert-danger py-2">{signError}</div>
      {/if}

      <!-- Signature Result & Verification -->
      {#if signature}
        <div class="border rounded p-3 bg-light">
          <div class="mb-3">
            <div class="d-flex justify-content-between align-items-center mb-1">
              <span class="small fw-medium">Signature</span>
              <button
                onclick={() => copyToClipboard(formatSignature(signature))}
                class="btn btn-outline-secondary btn-sm p-1"
                title="Copy signature"
              >
                <Copy size={14} />
              </button>
            </div>
            <code
              class="d-block p-2 bg-body-secondary rounded small"
              style="word-break: break-all; max-height: 80px; overflow-y: auto;"
            >
              {formatSignature(signature)}
            </code>
          </div>

          <hr />

          <!-- Verification -->
          <div class="mb-2">
            <label for="verifyPk" class="form-label small fw-medium">
              Verify with Public Key
            </label>
            <textarea
              id="verifyPk"
              class="form-control form-control-sm"
              bind:value={verifyPublicKey}
              placeholder="Public key (base64)"
              rows="3"
            ></textarea>
            <small class="text-muted">
              Uses p256 crate (independent of plugin)
            </small>
          </div>

          <SpinnerButton
            loading={isVerifying}
            disabled={!verifyPublicKey.trim()}
            label="Verify Signature"
            loadingLabel="Verifying..."
            onclick={verifySignature}
            class="btn btn-info btn-sm w-100"
          />

          {#if verifyError}
            <div class="alert alert-danger mt-2 mb-0 py-1 small">
              {verifyError}
            </div>
          {/if}

          {#if verifyResult !== null}
            <div
              class="alert mt-2 mb-0 py-2 {verifyResult
                ? 'alert-success'
                : 'alert-danger'}"
            >
              {verifyResult ? "✓ Valid Signature" : "✗ Invalid Signature"}
            </div>
          {/if}
        </div>
      {/if}
    {/if}
  </div>
</section>
