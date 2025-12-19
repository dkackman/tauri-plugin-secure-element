<script lang="ts">
  import {
    checkSecureElementSupport,
    deleteKey,
    generateSecureKey,
    listKeys,
    signWithKey,
    type AuthenticationMode,
  } from "tauri-plugin-secure-element-api";

  // Create Key Section
  let newKeyName = $state("");
  let createdKey = $state(null);
  let createKeyError = $state("");

  // List Keys Section
  let filterKeyName = $state("");
  let filterPublicKey = $state("");
  let keysList = $state([]);
  let listKeysError = $state("");

  // Sign Message Section
  let signKeyName = $state("");
  let messageToSign = $state("");
  let signature = $state<Uint8Array | null>(null);
  let signError = $state("");

  // Delete Key Section
  let deleteKeyName = $state("");
  let deletePublicKey = $state("");
  let deleteError = $state("");
  let deleteSuccess = $state(false);

  // Secure Element Support
  let secureElementSupported = $state(null);
  let teeSupported = $state(null);
  let canEnforceBiometricOnly = $state(null);
  let secureElementCheckError = $state("");

  // Authentication Mode
  let authMode = $state<AuthenticationMode>("pinOrBiometric");

  function _createKey() {
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
        _refreshKeysList();
      })
      .catch((err) => {
        createKeyError = err.toString();
      });
  }

  function _refreshKeysList() {
    listKeysError = "";
    const keyNameFilter = filterKeyName.trim() || undefined;
    const publicKeyFilter = filterPublicKey.trim() || undefined;
    listKeys(keyNameFilter, publicKeyFilter)
      .then((keys) => {
        keysList = keys;
      })
      .catch((err) => {
        listKeysError = err.toString();
      });
  }

  function _signMessage() {
    if (!signKeyName.trim()) {
      signError = "Please enter a key name";
      return;
    }
    if (!messageToSign.trim()) {
      signError = "Please enter a message to sign";
      return;
    }
    signError = "";
    signature = null;
    // Convert string to Uint8Array for signing
    const encoder = new TextEncoder();
    const dataBytes = encoder.encode(messageToSign);
    signWithKey(signKeyName.trim(), dataBytes)
      .then((sig) => {
        signature = sig;
      })
      .catch((err) => {
        signError = err.toString();
      });
  }

  function _deleteKey() {
    const keyName = deleteKeyName.trim() || undefined;
    const publicKey = deletePublicKey.trim() || undefined;

    if (!keyName && !publicKey) {
      deleteError = "Please enter either a key name or public key";
      return;
    }

    deleteError = "";
    deleteSuccess = false;
    deleteKey(keyName, publicKey)
      .then((success) => {
        deleteSuccess = success;
        if (success) {
          deleteKeyName = "";
          deletePublicKey = "";
          _refreshKeysList();
        }
      })
      .catch((err) => {
        deleteError = err.toString();
      });
  }

  function formatSignature(sig: Uint8Array | null) {
    if (!sig) return "";
    return Array.from(sig)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  function _checkSecureElementSupport() {
    console.log("[App] _checkSecureElementSupport called");
    secureElementCheckError = "";
    checkSecureElementSupport()
      .then((result) => {
        console.log("[App] checkSecureElementSupport success:", result);
        secureElementSupported = result.secureElementSupported;
        teeSupported = result.teeSupported;
        canEnforceBiometricOnly = result.canEnforceBiometricOnly;
      })
      .catch((err) => {
        console.error("[App] checkSecureElementSupport error:", err);
        secureElementCheckError = err.toString();
        secureElementSupported = false;
        teeSupported = false;
        canEnforceBiometricOnly = false;
      });
  }

  // Reset authMode if biometricOnly is selected but not supported
  $effect(() => {
    if (authMode === "biometricOnly" && canEnforceBiometricOnly === false) {
      authMode = "pinOrBiometric";
    }
  });

  // Load keys and check secure element support on mount
  _refreshKeysList();
  _checkSecureElementSupport();
</script>

<main class="container my-4">
  <h1 class="mb-4 pb-2 border-bottom">Secure Key Manager</h1>

  <!-- Secure Element Status -->
  <div class="card mb-4">
    <div class="card-body">
      <h5 class="card-title mb-3">Hardware Security Status</h5>
      {#if secureElementCheckError}
        <div class="alert alert-danger mb-0">
          <strong>Hardware Security:</strong> Error checking support
        </div>
      {:else if secureElementSupported !== null}
        <div class="d-flex flex-column gap-2">
          <div>
            <strong>Secure Element:</strong>
            <span
              class="badge {secureElementSupported
                ? 'bg-success'
                : 'bg-warning'} ms-2"
            >
              {secureElementSupported ? "✓ Supported" : "✗ Not Supported"}
            </span>
          </div>
          <div>
            <strong>TEE:</strong>
            <span
              class="badge {teeSupported ? 'bg-success' : 'bg-warning'} ms-2"
            >
              {teeSupported ? "✓ Supported" : "✗ Not Supported"}
            </span>
          </div>
          <div>
            <strong>Biometric-Only Enforcement:</strong>
            <span
              class="badge {canEnforceBiometricOnly
                ? 'bg-success'
                : 'bg-warning'} ms-2"
            >
              {canEnforceBiometricOnly ? "✓ Supported" : "✗ Not Supported"}
            </span>
          </div>
        </div>
      {:else}
        <div class="alert alert-info mb-0">
          <strong>Hardware Security:</strong> Checking...
        </div>
      {/if}
    </div>
  </div>

  <!-- Create Key Section -->
  <section class="card mb-4">
    <div class="card-body">
      <h2 class="card-title h5 mb-3">Create New Key</h2>
      <div class="mb-3">
        <label for="newKeyName" class="form-label">Key Name:</label>
        <input
          id="newKeyName"
          type="text"
          class="form-control"
          bind:value={newKeyName}
          placeholder="Enter unique key name"
          onkeydown={(e) => e.key === "Enter" && _createKey()}
        />
      </div>
      <div class="mb-3">
        <label for="authMode" class="form-label"
          >Authentication Mode (for this key):</label
        >
        <select id="authMode" bind:value={authMode} class="form-select">
          <option value="none">None</option>
          <option value="pinOrBiometric">PIN or Biometric (Default)</option>
          {#if canEnforceBiometricOnly === true}
            <option value="biometricOnly">Biometric Only</option>
          {/if}
        </select>
      </div>
      <button onclick={_createKey} class="btn btn-success">Create Key</button>
      {#if createKeyError}
        <div class="alert alert-danger mt-3 mb-0">Error: {createKeyError}</div>
      {/if}
      {#if createdKey}
        <div class="alert alert-success mt-3 mb-0">
          <strong>Key Created Successfully!</strong><br />
          <strong>Key Name:</strong>
          {createdKey.keyName}<br />
          <strong>Hardware Backing:</strong>
          <span class="badge bg-info ms-2">{createdKey.hardwareBacking}</span
          ><br />
          <strong>Public Key:</strong>
          <code class="d-block mt-2 p-2 bg-body-secondary rounded small"
            >{createdKey.publicKey}</code
          >
        </div>
      {/if}
    </div>
  </section>

  <!-- List Keys Section -->
  <section class="card mb-4">
    <div class="card-body">
      <h2 class="card-title h5 mb-3">List Keys</h2>
      <div class="mb-3">
        <label for="filterKeyName" class="form-label"
          >Filter by Key Name (optional):</label
        >
        <input
          id="filterKeyName"
          type="text"
          class="form-control"
          bind:value={filterKeyName}
          placeholder="Key name filter"
        />
      </div>
      <div class="mb-3">
        <label for="filterPublicKey" class="form-label"
          >Filter by Public Key (optional):</label
        >
        <input
          id="filterPublicKey"
          type="text"
          class="form-control"
          bind:value={filterPublicKey}
          placeholder="Public key filter"
        />
      </div>
      <button onclick={_refreshKeysList} class="btn btn-primary"
        >Refresh List</button
      >
      {#if listKeysError}
        <div class="alert alert-danger mt-3 mb-0">Error: {listKeysError}</div>
      {/if}
      {#if keysList.length > 0}
        <div class="mt-3">
          <h3 class="h6 mb-3">Found {keysList.length} key(s):</h3>
          {#each keysList as key}
            <div class="card mb-2">
              <div class="card-body">
                <div class="mb-2"><strong>Name:</strong> {key.keyName}</div>
                <div class="mb-2">
                  <strong>Requires Authentication:</strong>
                  {key.requiresAuthentication === undefined ||
                  key.requiresAuthentication === null
                    ? "Unknown"
                    : key.requiresAuthentication
                      ? "Yes"
                      : "No"}
                </div>
                <div>
                  <strong>Public Key:</strong>
                  <code class="d-block mt-1 p-2 bg-body-secondary rounded small"
                    >{key.publicKey}</code
                  >
                </div>
              </div>
            </div>
          {/each}
        </div>
      {:else if !listKeysError}
        <div class="alert alert-info mt-3 mb-0">No keys found</div>
      {/if}
    </div>
  </section>

  <!-- Sign Message Section -->
  <section class="card mb-4">
    <div class="card-body">
      <h2 class="card-title h5 mb-3">Sign Message</h2>
      <div class="mb-3">
        <label for="signKeyName" class="form-label">Key Name:</label>
        <input
          id="signKeyName"
          type="text"
          class="form-control"
          bind:value={signKeyName}
          placeholder="Enter key name to use"
        />
      </div>
      <div class="mb-3">
        <label for="messageToSign" class="form-label">Message to Sign:</label>
        <textarea
          id="messageToSign"
          class="form-control"
          bind:value={messageToSign}
          placeholder="Enter message to sign"
          rows="3"
        ></textarea>
      </div>
      <button onclick={_signMessage} class="btn btn-success"
        >Sign Message</button
      >
      {#if signError}
        <div class="alert alert-danger mt-3 mb-0">Error: {signError}</div>
      {/if}
      {#if signature}
        <div class="alert alert-success mt-3 mb-0">
          <strong>Signature Generated:</strong><br />
          <code class="d-block mt-2 p-2 bg-body-secondary rounded small"
            >{formatSignature(signature)}</code
          >
        </div>
      {/if}
    </div>
  </section>

  <!-- Delete Key Section -->
  <section class="card mb-4">
    <div class="card-body">
      <h2 class="card-title h5 mb-3">Delete Key</h2>
      <div class="mb-3">
        <label for="deleteKeyName" class="form-label"
          >Key Name (optional):</label
        >
        <input
          id="deleteKeyName"
          type="text"
          class="form-control"
          bind:value={deleteKeyName}
          placeholder="Enter key name to delete"
          onkeydown={(e) => e.key === "Enter" && _deleteKey()}
        />
      </div>
      <div class="mb-3">
        <label for="deletePublicKey" class="form-label"
          >Public Key (optional):</label
        >
        <input
          id="deletePublicKey"
          type="text"
          class="form-control"
          bind:value={deletePublicKey}
          placeholder="Enter public key (base64) to delete"
          onkeydown={(e) => e.key === "Enter" && _deleteKey()}
        />
        <small class="form-text text-muted"
          >At least one of key name or public key must be provided.</small
        >
      </div>
      <button onclick={_deleteKey} class="btn btn-danger">Delete Key</button>
      {#if deleteError}
        <div class="alert alert-danger mt-3 mb-0">Error: {deleteError}</div>
      {/if}
      {#if deleteSuccess}
        <div class="alert alert-success mt-3 mb-0">
          Key deleted successfully!
        </div>
      {/if}
    </div>
  </section>
</main>
