<script lang="ts">
  import { Copy, Key, Plus, Trash2 } from "lucide-svelte";
  import {
    deleteKey,
    generateSecureKey,
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
  let createdKey = $state<{ keyName: string; hardwareBacking: string } | null>(
    null
  );
  let createKeyError = $state("");
  let showCreateForm = $state(false);
  let authMode = $state<AuthenticationMode>("pinOrBiometric");

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
    try {
      const success = await deleteKey(keyName);
      if (success) {
        if (selectedKeyName === keyName) {
          selectedKeyName = "";
        }
        onRefreshKeys();
      }
    } catch (err) {
      onDeleteError(err instanceof Error ? err.message : String(err));
    }
  }
</script>

<section class="card h-100">
  <div class="card-header d-flex justify-content-between align-items-center">
    <h2 class="h5 mb-0">
      <Key size={18} class="me-2" />
      Your Keys
    </h2>
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
        <span class="badge bg-info ms-1">{createdKey.hardwareBacking}</span>
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
        {#each keysList as key}
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
              <div class="d-flex gap-1 ms-2">
                <button
                  onclick={() => copyToClipboard(key.publicKey)}
                  class="btn btn-outline-secondary btn-sm p-1"
                  title="Copy public key"
                >
                  <Copy size={14} />
                </button>
                <button
                  onclick={() => deleteKeyByName(key.keyName)}
                  class="btn btn-outline-danger btn-sm p-1"
                  title="Delete key"
                >
                  <Trash2 size={14} />
                </button>
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
