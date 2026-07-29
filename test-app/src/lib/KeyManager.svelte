<script lang="ts">
  import { Copy, Key, Plus, ShieldCheck, Trash2 } from "@lucide/svelte";
  import {
    deleteKey,
    generateSecureKey,
    isSecureElementError,
    type AuthenticationMode,
    type KeyInfo,
  } from "tauri-plugin-secure-element-api";
  import { copyToClipboard } from "./utils.js";

  let {
    keysList,
    listKeysError,
    selectedKeyName = $bindable(""),
    canEnforceBiometricOnly,
    onRefreshKeys,
    onDeleteError,
  }: {
    keysList: KeyInfo[];
    listKeysError: string;
    selectedKeyName: string;
    canEnforceBiometricOnly: boolean | null;
    onRefreshKeys: () => void;
    onDeleteError: (msg: string) => void;
  } = $props();

  let newKeyName = $state("");
  let createdKey = $state<{ keyName: string } | null>(null);
  let createKeyError = $state("");
  let showCreateForm = $state(false);
  let authMode = $state<AuthenticationMode>("pinOrBiometric");
  let pendingDeleteKey = $state("");

  // Exercises `deleteKey`'s requireAuth option. Off by default, matching the
  // plugin default — deletion is unauthenticated on every platform unless the
  // caller asks for a prompt.
  let requireAuthOnDelete = $state(false);
  // Cancelling the prompt is an expected outcome, not a failure, so it gets its
  // own notice rather than being routed to the error banner.
  let deleteNotice = $state("");

  $effect(() => {
    if (authMode === "biometricOnly" && canEnforceBiometricOnly === false) {
      authMode = "pinOrBiometric";
    }
  });

  function createKey() {
    if (!newKeyName.trim()) {
      createKeyError = "Please enter a key name";
      return;
    }
    createKeyError = "";
    createdKey = null;
    generateSecureKey(newKeyName.trim(), authMode)
      .then((result) => {
        createdKey = result;
        newKeyName = "";
        showCreateForm = false;
        onRefreshKeys();
      })
      .catch((err) => {
        createKeyError = err.toString();
      });
  }

  async function deleteKeyByName(keyName: string) {
    deleteNotice = "";
    try {
      const success = await deleteKey(keyName, undefined, {
        requireAuth: requireAuthOnDelete,
        reason: `Confirm deletion of key "${keyName}"`,
      });
      if (success) {
        if (selectedKeyName === keyName) {
          selectedKeyName = "";
        }
        if (requireAuthOnDelete) {
          deleteNotice = `Authenticated and deleted "${keyName}"`;
        }
        onRefreshKeys();
      }
    } catch (err) {
      // The point of the error codes: a dismissed prompt is a normal outcome
      // and should not look like a failure.
      if (isSecureElementError(err) && err.code === "userCancelled") {
        deleteNotice = `Authentication cancelled — "${keyName}" was not deleted`;
        return;
      }
      const detail = isSecureElementError(err)
        ? `${err.message} (${err.code})`
        : err instanceof Error
          ? err.message
          : String(err);
      onDeleteError(detail);
    }
  }
</script>

<section class="card h-100">
  <!-- flex-wrap so the toggle and button drop to a second row on phone widths
       instead of squeezing the title and button into two lines each -->
  <div
    class="card-header d-flex justify-content-between align-items-center flex-wrap gap-2"
  >
    <h2 class="h5 mb-0 text-nowrap">
      <Key size={18} class="me-2" />
      Your Keys
    </h2>
    <div class="d-flex align-items-center gap-3 ms-auto">
      <div
        class="form-check form-switch mb-0"
        title="Pass requireAuth to deleteKey, so deletion prompts for biometric or device PIN. No platform requires this on its own."
      >
        <input
          class="form-check-input"
          type="checkbox"
          role="switch"
          id="require-auth-on-delete"
          bind:checked={requireAuthOnDelete}
        />
        <label
          class="form-check-label small text-nowrap"
          for="require-auth-on-delete"
        >
          <ShieldCheck size={14} class="me-1" />Auth to delete
        </label>
      </div>
      <button
        onclick={() => (showCreateForm = !showCreateForm)}
        class="btn btn-sm {showCreateForm
          ? 'btn-outline-secondary'
          : 'btn-success'}"
      >
        {#if showCreateForm}
          Cancel
        {:else}
          <Plus size={16} class="me-1" /> New Key
        {/if}
      </button>
    </div>
  </div>

  <div class="card-body">
    <!-- Create Key Form (collapsible) -->
    {#if showCreateForm}
      <div class="border rounded p-3 mb-3 bg-light">
        <div class="mb-2">
          <input
            type="text"
            class="form-control form-control-sm"
            bind:value={newKeyName}
            placeholder="Key name"
            onkeydown={(e) => e.key === "Enter" && createKey()}
          />
        </div>
        <div class="mb-2">
          <select bind:value={authMode} class="form-select form-select-sm">
            <option value="none">No Authentication</option>
            <option value="pinOrBiometric">PIN or Biometric</option>
            {#if canEnforceBiometricOnly === true}
              <option value="biometricOnly">Biometric Only</option>
            {/if}
          </select>
        </div>
        <button onclick={createKey} class="btn btn-success btn-sm w-100">
          Create Key
        </button>
        {#if createKeyError}
          <div class="alert alert-danger mt-2 mb-0 py-1 px-2 small">
            {createKeyError}
          </div>
        {/if}
      </div>
    {/if}

    <!-- Success message for created key -->
    {#if createdKey}
      <div class="alert alert-success py-2 px-3 small">
        <strong>Created:</strong>
        {createdKey.keyName}
      </div>
    {/if}

    <!-- Outcome of an authenticated delete (including a cancelled prompt) -->
    {#if deleteNotice}
      <div
        class="alert alert-info d-flex justify-content-between align-items-center py-2 px-3 small"
      >
        <span>{deleteNotice}</span>
        <button
          type="button"
          class="btn-close btn-sm"
          aria-label="Dismiss"
          onclick={() => (deleteNotice = "")}
        ></button>
      </div>
    {/if}

    <!-- Keys List -->
    {#if listKeysError}
      <div class="alert alert-danger py-2">{listKeysError}</div>
    {/if}

    {#if keysList.length === 0}
      <div class="text-center text-muted py-4">
        <Key size={32} class="mb-2 opacity-50" />
        <p class="mb-0">No keys yet</p>
        <small>Create your first secure key</small>
      </div>
    {:else}
      <div class="list-group list-group-flush">
        {#each keysList as key (key.keyName)}
          <div
            class="list-group-item px-0 {selectedKeyName === key.keyName
              ? 'bg-primary-subtle'
              : ''}"
          >
            <div class="d-flex justify-content-between align-items-start">
              <div class="flex-grow-1 min-width-0">
                <button
                  onclick={() => (selectedKeyName = key.keyName)}
                  class="btn btn-link p-0 text-start text-decoration-none fw-medium"
                >
                  {key.keyName}
                </button>
                <div
                  class="small text-muted text-truncate"
                  style="max-width: 200px;"
                  title={key.publicKey}
                >
                  {key.publicKey.slice(0, 20)}...
                </div>
              </div>
              <div class="d-flex gap-1 ms-2 align-items-center">
                {#if pendingDeleteKey === key.keyName}
                  <span class="small text-danger me-1 text-nowrap">
                    {requireAuthOnDelete ? "Delete (auth)?" : "Delete?"}
                  </span>
                  <button
                    onclick={() => {
                      deleteKeyByName(key.keyName);
                      pendingDeleteKey = "";
                    }}
                    class="btn btn-danger btn-sm py-0 px-2"
                  >
                    Yes
                  </button>
                  <button
                    onclick={() => (pendingDeleteKey = "")}
                    class="btn btn-outline-secondary btn-sm py-0 px-2"
                  >
                    No
                  </button>
                {:else}
                  <button
                    onclick={() => copyToClipboard(key.publicKey)}
                    class="btn btn-outline-secondary btn-sm p-1"
                    title="Copy public key"
                  >
                    <Copy size={14} />
                  </button>
                  <button
                    onclick={() => (pendingDeleteKey = key.keyName)}
                    class="btn btn-outline-danger btn-sm p-1"
                    title="Delete key"
                  >
                    <Trash2 size={14} />
                  </button>
                {/if}
              </div>
            </div>
          </div>
        {/each}
      </div>
    {/if}
  </div>
</section>

<style>
  .min-width-0 {
    min-width: 0;
  }
</style>
