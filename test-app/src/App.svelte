<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { Copy, Trash2 } from "lucide-svelte";
  import {
    checkSecureElementSupport,
    deleteKey,
    generateSecureKey,
    listKeys,
    signWithKey,
    type AuthenticationMode,
  } from "tauri-plugin-secure-element-api";

  // Test Runner Section
  type TestResult = {
    name: string;
    status: "pending" | "running" | "passed" | "failed";
    message?: string;
    duration?: number;
  };
  let testResults = $state<TestResult[]>([]);
  let testLog = $state<string[]>([]);
  let isTestRunning = $state(false);
  let testSummary = $state<{
    total: number;
    passed: number;
    failed: number;
    duration: number;
  } | null>(null);

  function log(message: string, type: "info" | "success" | "error" = "info") {
    const timestamp = new Date().toLocaleTimeString();
    const prefix = type === "success" ? "✓" : type === "error" ? "✗" : "→";
    testLog = [...testLog, `[${timestamp}] ${prefix} ${message}`];
  }

  function clearLog() {
    testLog = [];
    testResults = [];
    testSummary = null;
  }

  async function runTest(
    name: string,
    testFn: () => Promise<void>
  ): Promise<boolean> {
    const startTime = Date.now();
    log(`Running: ${name}`);

    // Update test status to running
    testResults = testResults.map((t) =>
      t.name === name ? { ...t, status: "running" as const } : t
    );

    try {
      await testFn();
      const duration = Date.now() - startTime;
      log(`${name} - PASSED (${duration}ms)`, "success");
      testResults = testResults.map((t) =>
        t.name === name ? { ...t, status: "passed" as const, duration } : t
      );
      return true;
    } catch (err) {
      const duration = Date.now() - startTime;
      const errorMsg = err instanceof Error ? err.message : String(err);
      log(`${name} - FAILED: ${errorMsg}`, "error");
      testResults = testResults.map((t) =>
        t.name === name
          ? { ...t, status: "failed" as const, message: errorMsg, duration }
          : t
      );
      return false;
    }
  }

  async function runAllTests() {
    if (isTestRunning) return;
    isTestRunning = true;
    clearLog();

    const startTime = Date.now();
    const testKeyName = `test_key_${Date.now()}`;
    let testPublicKey = "";
    let passed = 0;
    let failed = 0;

    // Define all tests
    const tests: { name: string; fn: () => Promise<void> }[] = [
      {
        name: "Check Secure Element Support",
        fn: async () => {
          const result = await checkSecureElementSupport();
          if (typeof result.secureElementSupported !== "boolean") {
            throw new Error("Invalid response: missing secureElementSupported");
          }
          if (typeof result.teeSupported !== "boolean") {
            throw new Error("Invalid response: missing teeSupported");
          }
          log(
            `  Secure Element: ${result.secureElementSupported}, TEE: ${result.teeSupported}, BiometricOnly: ${result.canEnforceBiometricOnly}`
          );
        },
      },
      {
        name: "Generate Secure Key (authMode: none)",
        fn: async () => {
          const result = await generateSecureKey(testKeyName, "none");
          if (!result.keyName) throw new Error("Missing keyName in response");
          if (!result.publicKey)
            throw new Error("Missing publicKey in response");
          if (!result.hardwareBacking)
            throw new Error("Missing hardwareBacking");
          testPublicKey = result.publicKey;
          log(`  Created key: ${result.keyName} (${result.hardwareBacking})`);
        },
      },
      {
        name: "List Keys - Verify Key Exists",
        fn: async () => {
          const keys = await listKeys(testKeyName);
          if (!keys || keys.length === 0) {
            throw new Error(`Key '${testKeyName}' not found in list`);
          }
          const foundKey = keys.find((k) => k.keyName === testKeyName);
          if (!foundKey) throw new Error("Key not in filtered list");
          log(`  Found ${keys.length} key(s) matching filter`);
        },
      },
      {
        name: "List Keys - Filter by Public Key",
        fn: async () => {
          const keys = await listKeys(undefined, testPublicKey);
          if (!keys || keys.length === 0) {
            throw new Error("Key not found by public key filter");
          }
          log(`  Found key by public key filter`);
        },
      },
      {
        name: "Sign Message with Key",
        fn: async () => {
          const message = "Test message for signing";
          const encoder = new TextEncoder();
          const dataBytes = encoder.encode(message);
          const signature = await signWithKey(testKeyName, dataBytes);
          if (!signature || signature.length === 0) {
            throw new Error("Empty signature returned");
          }
          log(`  Signature length: ${signature.length} bytes`);
        },
      },
      {
        name: "Verify Signature (p256 crate)",
        fn: async () => {
          const message = "Test message for p256 verification";
          const encoder = new TextEncoder();
          const dataBytes = encoder.encode(message);

          // Sign the message
          const signature = await signWithKey(testKeyName, dataBytes);
          if (!signature || signature.length === 0) {
            throw new Error("Empty signature returned");
          }

          // Verify using Rust p256 crate (independent of plugin)
          const messageBytes = Array.from(dataBytes);
          const signatureBytes = Array.from(signature);

          const isValid = await invoke<boolean>("verify_signature", {
            publicKeyBase64: testPublicKey,
            message: messageBytes,
            signatureDer: signatureBytes,
          });

          if (!isValid) {
            throw new Error(
              "Signature verification failed - signature is invalid"
            );
          }
          log(`  Signature verified successfully using p256 crate`);
        },
      },
      {
        name: "Sign Different Message - Produces Different Signature",
        fn: async () => {
          const encoder = new TextEncoder();
          const sig1 = await signWithKey(
            testKeyName,
            encoder.encode("Message 1")
          );
          const sig2 = await signWithKey(
            testKeyName,
            encoder.encode("Message 2")
          );

          // Compare signatures
          const sig1Hex = Array.from(sig1)
            .map((b) => b.toString(16).padStart(2, "0"))
            .join("");
          const sig2Hex = Array.from(sig2)
            .map((b) => b.toString(16).padStart(2, "0"))
            .join("");

          if (sig1Hex === sig2Hex) {
            throw new Error(
              "Signatures should be different for different messages"
            );
          }
          log(`  Different messages produce different signatures`);
        },
      },
      {
        name: "Delete Key by Name",
        fn: async () => {
          const success = await deleteKey(testKeyName);
          if (!success) throw new Error("Delete returned false");
          log(`  Key deleted successfully`);
        },
      },
      {
        name: "Verify Key is Deleted",
        fn: async () => {
          const keys = await listKeys(testKeyName);
          if (keys && keys.length > 0) {
            throw new Error("Key still exists after deletion");
          }
          log(`  Key no longer exists (as expected)`);
        },
      },
      {
        name: "Delete Non-existent Key (Idempotent)",
        fn: async () => {
          const success = await deleteKey("non_existent_key_12345");
          if (!success) throw new Error("Idempotent delete should return true");
          log(`  Deleting non-existent key succeeds (idempotent)`);
        },
      },
      {
        name: "Full Workflow - Create, Sign, Verify, Delete",
        fn: async () => {
          const workflowKey = `workflow_key_${Date.now()}`;

          // Create
          const { publicKey } = await generateSecureKey(workflowKey, "none");
          log(`  Created: ${workflowKey}`);

          // Sign
          const encoder = new TextEncoder();
          const message = "workflow test message";
          const sig = await signWithKey(workflowKey, encoder.encode(message));
          log(`  Signed message (${sig.length} bytes)`);

          // Verify using p256 crate
          const isValid = await invoke<boolean>("verify_signature", {
            publicKeyBase64: publicKey,
            message: Array.from(encoder.encode(message)),
            signatureDer: Array.from(sig),
          });
          if (!isValid) throw new Error("Signature verification failed");
          log(`  Verified signature with p256 crate`);

          // Delete
          await deleteKey(workflowKey);
          log(`  Deleted: ${workflowKey}`);

          // Verify deleted
          const keys = await listKeys(workflowKey);
          if (keys && keys.length > 0) throw new Error("Key not deleted");
          log(`  Verified key is deleted`);
        },
      },
    ];

    // Initialize test results
    testResults = tests.map((t) => ({
      name: t.name,
      status: "pending" as const,
    }));

    log("═══════════════════════════════════════");
    log("Starting Integration Tests");
    log("═══════════════════════════════════════");

    // Run all tests
    for (const test of tests) {
      const success = await runTest(test.name, test.fn);
      if (success) passed++;
      else failed++;
    }

    const totalDuration = Date.now() - startTime;
    log("═══════════════════════════════════════");
    log(
      `Tests Complete: ${passed} passed, ${failed} failed (${totalDuration}ms)`
    );
    log("═══════════════════════════════════════");

    testSummary = {
      total: tests.length,
      passed,
      failed,
      duration: totalDuration,
    };

    isTestRunning = false;
  }

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

  // Verify Signature Section (within Sign Message)
  let verifyPublicKey = $state("");
  let verifyResult = $state<boolean | null>(null);
  let verifyError = $state("");
  let isVerifying = $state(false);

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
    verifyResult = null;
    verifyError = "";
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

  async function _verifySignature() {
    if (!signature) {
      verifyError = "No signature to verify. Sign a message first.";
      return;
    }
    if (!verifyPublicKey.trim()) {
      verifyError = "Please enter the public key for verification";
      return;
    }
    if (!messageToSign.trim()) {
      verifyError = "Please enter the message that was signed";
      return;
    }

    verifyError = "";
    verifyResult = null;
    isVerifying = true;

    try {
      const encoder = new TextEncoder();
      const messageBytes = Array.from(encoder.encode(messageToSign));
      const signatureBytes = Array.from(signature);

      const result = await invoke<boolean>("verify_signature", {
        publicKeyBase64: verifyPublicKey.trim(),
        message: messageBytes,
        signatureDer: signatureBytes,
      });

      verifyResult = result;
    } catch (err) {
      verifyError = err instanceof Error ? err.message : String(err);
    } finally {
      isVerifying = false;
    }
  }

  async function _deleteKeyByName(keyName: string) {
    try {
      const success = await deleteKey(keyName);
      if (success) {
        _refreshKeysList();
      }
    } catch (err) {
      // Error handling - could show a toast or update listKeysError
      console.error("Failed to delete key:", err);
      listKeysError = err instanceof Error ? err.message : String(err);
    }
  }

  async function _copyPublicKey(publicKey: string) {
    try {
      await navigator.clipboard.writeText(publicKey);
      // Visual feedback could be added here (toast, icon change, etc.)
    } catch (err) {
      console.error("Failed to copy public key:", err);
      listKeysError = err instanceof Error ? err.message : String(err);
    }
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

  <!-- Integration Test Runner -->
  <section class="card mb-4 border-primary">
    <div
      class="card-header bg-primary text-white d-flex justify-content-between align-items-center"
    >
      <h5 class="mb-0">Integration Test Runner</h5>
      {#if testSummary}
        <span
          class="badge {testSummary.failed === 0 ? 'bg-success' : 'bg-danger'}"
        >
          {testSummary.passed}/{testSummary.total} passed
        </span>
      {/if}
    </div>
    <div class="card-body">
      <div class="d-flex gap-2 mb-3">
        <button
          onclick={runAllTests}
          class="btn btn-primary"
          disabled={isTestRunning}
        >
          {#if isTestRunning}
            <span class="spinner-border spinner-border-sm me-2" role="status"
            ></span>
            Running Tests...
          {:else}
            Run All Tests
          {/if}
        </button>
        <button
          onclick={clearLog}
          class="btn btn-outline-secondary"
          disabled={isTestRunning}
        >
          Clear
        </button>
      </div>

      <!-- Test Status Grid -->
      {#if testResults.length > 0}
        <div class="mb-3">
          <div class="d-flex flex-wrap gap-2">
            {#each testResults as test}
              <span
                class="badge {test.status === 'passed'
                  ? 'bg-success'
                  : test.status === 'failed'
                    ? 'bg-danger'
                    : test.status === 'running'
                      ? 'bg-warning text-dark'
                      : 'bg-secondary'}"
                title={test.message || test.name}
              >
                {test.status === "running"
                  ? "..."
                  : test.status === "passed"
                    ? "✓"
                    : test.status === "failed"
                      ? "✗"
                      : "○"}
                {test.name.length > 25
                  ? test.name.slice(0, 25) + "..."
                  : test.name}
              </span>
            {/each}
          </div>
        </div>
      {/if}

      <!-- Console Output -->
      <div
        class="bg-dark text-light p-3 rounded font-monospace"
        style="height: 300px; overflow-y: auto; font-size: 0.85rem;"
      >
        {#if testLog.length === 0}
          <span class="text-muted"
            >Click "Run All Tests" to start integration tests...</span
          >
        {:else}
          {#each testLog as line}
            <div
              class={line.includes("PASSED")
                ? "text-success"
                : line.includes("FAILED")
                  ? "text-danger"
                  : line.includes("═")
                    ? "text-info"
                    : "text-light"}
            >
              {line}
            </div>
          {/each}
        {/if}
      </div>

      <!-- Summary -->
      {#if testSummary}
        <div
          class="mt-3 alert {testSummary.failed === 0
            ? 'alert-success'
            : 'alert-danger'} mb-0"
        >
          <strong>Test Summary:</strong>
          {testSummary.passed} passed, {testSummary.failed} failed ({testSummary.total}
          total) in {testSummary.duration}ms
        </div>
      {/if}
    </div>
  </section>

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
                <div
                  class="d-flex justify-content-between align-items-center mb-2"
                >
                  <div><strong>Name:</strong> {key.keyName}</div>
                  <div class="d-flex gap-2">
                    <button
                      onclick={() => _copyPublicKey(key.publicKey)}
                      class="btn btn-outline-secondary btn-sm"
                      title="Copy public key"
                    >
                      <Copy size={16} />
                    </button>
                    <button
                      onclick={() => _deleteKeyByName(key.keyName)}
                      class="btn btn-outline-danger btn-sm"
                      title="Delete key"
                    >
                      <Trash2 size={16} />
                    </button>
                  </div>
                </div>
                <div>
                  <strong>Public Key:</strong>
                  <code
                    class="d-block mt-1 p-2 bg-body-secondary rounded small text-break"
                    style="word-break: break-all; overflow-wrap: break-word;"
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

        <!-- Verify Signature Sub-section -->
        <div class="card mt-3 border-info">
          <div class="card-body">
            <h3 class="card-title h6 mb-3">
              Verify Signature (using p256 crate)
            </h3>
            <div class="mb-3">
              <label for="verifyPublicKey" class="form-label"
                >Public Key (base64):</label
              >
              <input
                id="verifyPublicKey"
                type="text"
                class="form-control"
                bind:value={verifyPublicKey}
                placeholder="Paste the public key to verify against"
              />
              <small class="form-text text-muted">
                This verifies the signature using Rust's p256 crate, independent
                of the plugin.
              </small>
            </div>
            <button
              onclick={_verifySignature}
              class="btn btn-info"
              disabled={isVerifying}
            >
              {#if isVerifying}
                <span
                  class="spinner-border spinner-border-sm me-2"
                  role="status"
                ></span>
                Verifying...
              {:else}
                Verify Signature
              {/if}
            </button>
            {#if verifyError}
              <div class="alert alert-danger mt-3 mb-0">
                Error: {verifyError}
              </div>
            {/if}
            {#if verifyResult !== null}
              <div
                class="alert {verifyResult
                  ? 'alert-success'
                  : 'alert-danger'} mt-3 mb-0"
              >
                <strong>Verification Result:</strong>
                {verifyResult
                  ? "✓ Signature is VALID"
                  : "✗ Signature is INVALID"}
              </div>
            {/if}
          </div>
        </div>
      {/if}
    </div>
  </section>
</main>
