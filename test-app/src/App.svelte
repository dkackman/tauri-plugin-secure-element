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
  let deleteError = $state("");
  let deleteSuccess = $state(false);

  // Secure Element Support
  let secureElementSupported = $state(null);
  let teeSupported = $state(null);
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
    if (!deleteKeyName.trim()) {
      deleteError = "Please enter a key name";
      return;
    }
    deleteError = "";
    deleteSuccess = false;
    deleteKey(deleteKeyName.trim())
      .then((success) => {
        deleteSuccess = success;
        if (success) {
          deleteKeyName = "";
          _refreshKeysList();
        }
      })
      .catch((err) => {
        deleteError = err.toString();
      });
  }

  function formatPublicKey(pubKey) {
    // Show first 20 and last 20 characters for readability
    if (pubKey.length > 40) {
      return `${pubKey.substring(0, 20)}...${pubKey.substring(pubKey.length - 20)}`;
    }
    return pubKey;
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
      })
      .catch((err) => {
        console.error("[App] checkSecureElementSupport error:", err);
        secureElementCheckError = err.toString();
        secureElementSupported = false;
        teeSupported = false;
      });
  }

  // Load keys and check secure element support on mount
  _refreshKeysList();
  _checkSecureElementSupport();
</script>

<main class="container">
  <h1>Secure Key Manager</h1>

  <!-- Secure Element Status -->
  <div class="secure-element-status">
    {#if secureElementCheckError}
      <div class="status-item error">
        <span class="status-label">Hardware Security:</span>
        <span class="status-value">Error checking support</span>
      </div>
    {:else if secureElementSupported !== null}
      <div class="status-item {secureElementSupported ? 'success' : 'warning'}">
        <span class="status-label">Secure Element:</span>
        <span class="status-value">
          {secureElementSupported ? "✓ Supported" : "✗ Not Supported"}
        </span>
      </div>
      <div class="status-item {teeSupported ? 'success' : 'warning'}">
        <span class="status-label">TEE:</span>
        <span class="status-value">
          {teeSupported ? "✓ Supported" : "✗ Not Supported"}
        </span>
      </div>
    {:else}
      <div class="status-item info">
        <span class="status-label">Hardware Security:</span>
        <span class="status-value">Checking...</span>
      </div>
    {/if}
  </div>

  <!-- Create Key Section -->
  <section class="section">
    <h2>Create New Key</h2>
    <div class="form-group">
      <label for="newKeyName">Key Name:</label>
      <input
        id="newKeyName"
        type="text"
        bind:value={newKeyName}
        placeholder="Enter unique key name"
        onkeydown={(e) => e.key === "Enter" && _createKey()}
      />
      <label for="authMode">Authentication Mode (for this key):</label>
      <select id="authMode" bind:value={authMode} class="auth-mode-select">
        <option value="none">None</option>
        <option value="pinOrBiometric">PIN or Biometric (Default)</option>
        <option value="biometricOnly">Biometric Only</option>
      </select>
      <button onclick={_createKey} class="primary">Create Key</button>
    </div>
    {#if createKeyError}
      <div class="error">Error: {createKeyError}</div>
    {/if}
    {#if createdKey}
      <div class="success">
        <strong>Key Created Successfully!</strong><br />
        <strong>Key Name:</strong>
        {createdKey.keyName}<br />
        <strong>Public Key:</strong>
        <code class="public-key">{createdKey.publicKey}</code>
      </div>
    {/if}
  </section>

  <!-- List Keys Section -->
  <section class="section">
    <h2>List Keys</h2>
    <div class="form-group">
      <label for="filterKeyName">Filter by Key Name (optional):</label>
      <input
        id="filterKeyName"
        type="text"
        bind:value={filterKeyName}
        placeholder="Key name filter"
      />
      <label for="filterPublicKey">Filter by Public Key (optional):</label>
      <input
        id="filterPublicKey"
        type="text"
        bind:value={filterPublicKey}
        placeholder="Public key filter"
      />
      <button onclick={_refreshKeysList}>Refresh List</button>
    </div>
    {#if listKeysError}
      <div class="error">Error: {listKeysError}</div>
    {/if}
    {#if keysList.length > 0}
      <div class="keys-list">
        <h3>Found {keysList.length} key(s):</h3>
        {#each keysList as key}
          <div class="key-item">
            <div><strong>Name:</strong> {key.keyName}</div>
            <div>
              <strong>Requires Authentication:</strong>
              {key.requiresAuthentication === undefined || key.requiresAuthentication === null
                ? "Unknown"
                : key.requiresAuthentication
                  ? "Yes"
                  : "No"}
            </div>
            <div>
              <strong>Public Key:</strong>
              <code class="public-key">{formatPublicKey(key.publicKey)}</code>
            </div>
            <div class="full-key"><code>{key.publicKey}</code></div>
          </div>
        {/each}
      </div>
    {:else if !listKeysError}
      <div class="info">No keys found</div>
    {/if}
  </section>

  <!-- Sign Message Section -->
  <section class="section">
    <h2>Sign Message</h2>
    <div class="form-group">
      <label for="signKeyName">Key Name:</label>
      <input
        id="signKeyName"
        type="text"
        bind:value={signKeyName}
        placeholder="Enter key name to use"
      />
      <label for="messageToSign">Message to Sign:</label>
      <textarea
        id="messageToSign"
        bind:value={messageToSign}
        placeholder="Enter message to sign"
        rows="3"
      ></textarea>
      <button onclick={_signMessage} class="primary">Sign Message</button>
    </div>
    {#if signError}
      <div class="error">Error: {signError}</div>
    {/if}
    {#if signature}
      <div class="success">
        <strong>Signature Generated:</strong><br />
        <code class="signature">{formatSignature(signature)}</code>
      </div>
    {/if}
  </section>

  <!-- Delete Key Section -->
  <section class="section">
    <h2>Delete Key</h2>
    <div class="form-group">
      <label for="deleteKeyName">Key Name:</label>
      <input
        id="deleteKeyName"
        type="text"
        bind:value={deleteKeyName}
        placeholder="Enter key name to delete"
        onkeydown={(e) => e.key === "Enter" && _deleteKey()}
      />
      <button onclick={_deleteKey} class="danger">Delete Key</button>
    </div>
    {#if deleteError}
      <div class="error">Error: {deleteError}</div>
    {/if}
    {#if deleteSuccess}
      <div class="success">Key deleted successfully!</div>
    {/if}
  </section>
</main>

<style>
  .container {
    max-width: 900px;
    margin: 0 auto;
    padding: 20px;
    font-family:
      -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu,
      Cantarell, sans-serif;
  }

  h1 {
    color: #333;
    border-bottom: 2px solid #4caf50;
    padding-bottom: 10px;
    margin-bottom: 15px;
  }

  .secure-element-status {
    margin-bottom: 20px;
    padding: 12px;
    background: #f5f5f5;
    border-radius: 6px;
    border-left: 4px solid #2196f3;
  }

  .status-item {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 14px;
  }

  .status-item.success {
    color: #2e7d32;
    border-left-color: #4caf50;
  }

  .status-item.warning {
    color: #f57c00;
    border-left-color: #ff9800;
  }

  .status-item.error {
    color: #c62828;
    border-left-color: #f44336;
  }

  .status-item.info {
    color: #1565c0;
    border-left-color: #2196f3;
  }

  .status-label {
    font-weight: 600;
  }

  .status-value {
    font-weight: 500;
  }

  .auth-mode-select {
    padding: 10px;
    border: 1px solid #ccc;
    border-radius: 4px;
    font-size: 14px;
    font-family: inherit;
    background: white;
    cursor: pointer;
  }

  .auth-mode-select:hover {
    border-color: #4caf50;
  }

  .auth-mode-select:focus {
    outline: none;
    border-color: #4caf50;
    box-shadow: 0 0 0 2px rgba(76, 175, 80, 0.2);
  }

  h2 {
    color: #555;
    margin-top: 0;
    font-size: 1.3em;
  }

  h3 {
    color: #666;
    font-size: 1.1em;
    margin: 10px 0;
  }

  .section {
    background: #f9f9f9;
    border: 1px solid #ddd;
    border-radius: 8px;
    padding: 20px;
    margin-bottom: 20px;
  }

  .form-group {
    display: flex;
    flex-direction: column;
    gap: 10px;
    margin-bottom: 15px;
  }

  .form-group label {
    font-weight: 600;
    color: #555;
    margin-top: 10px;
  }

  .form-group label:first-child {
    margin-top: 0;
  }

  input,
  textarea {
    padding: 10px;
    border: 1px solid #ccc;
    border-radius: 4px;
    font-size: 14px;
    font-family: inherit;
  }

  textarea {
    resize: vertical;
    min-height: 60px;
  }

  button {
    padding: 10px 20px;
    border: none;
    border-radius: 4px;
    font-size: 14px;
    font-weight: 600;
    cursor: pointer;
    transition: background-color 0.2s;
    margin-top: 10px;
  }

  button.primary {
    background-color: #4caf50;
    color: white;
  }

  button.primary:hover {
    background-color: #45a049;
  }

  button.danger {
    background-color: #f44336;
    color: white;
  }

  button.danger:hover {
    background-color: #da190b;
  }

  button:not(.primary):not(.danger) {
    background-color: #2196f3;
    color: white;
  }

  button:not(.primary):not(.danger):hover {
    background-color: #0b7dda;
  }

  .error {
    background-color: #ffebee;
    color: #c62828;
    padding: 10px;
    border-radius: 4px;
    border-left: 4px solid #c62828;
    margin-top: 10px;
  }

  .success {
    background-color: #e8f5e9;
    color: #2e7d32;
    padding: 10px;
    border-radius: 4px;
    border-left: 4px solid #2e7d32;
    margin-top: 10px;
  }

  .info {
    background-color: #e3f2fd;
    color: #1565c0;
    padding: 10px;
    border-radius: 4px;
    border-left: 4px solid #1565c0;
    margin-top: 10px;
  }

  .keys-list {
    margin-top: 15px;
  }

  .key-item {
    background: white;
    border: 1px solid #ddd;
    border-radius: 4px;
    padding: 15px;
    margin-bottom: 10px;
  }

  .key-item div {
    margin-bottom: 8px;
  }

  .key-item div:last-child {
    margin-bottom: 0;
  }

  .full-key {
    font-size: 11px;
    color: #666;
    word-break: break-all;
    margin-top: 8px;
    padding-top: 8px;
    border-top: 1px solid #eee;
  }

  code {
    background-color: #f5f5f5;
    padding: 2px 6px;
    border-radius: 3px;
    font-family: "Monaco", "Courier New", monospace;
    font-size: 12px;
    word-break: break-all;
  }

  .public-key {
    font-size: 11px;
    display: inline-block;
    max-width: 100%;
  }

  .signature {
    display: block;
    padding: 10px;
    background-color: #f5f5f5;
    border-radius: 4px;
    margin-top: 10px;
    word-break: break-all;
    font-size: 11px;
  }
</style>
