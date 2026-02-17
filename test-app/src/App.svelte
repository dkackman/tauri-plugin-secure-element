<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { platform } from "@tauri-apps/plugin-os";
  import {
    ChevronDown,
    ChevronUp,
    Copy,
    Key,
    Plus,
    Trash2,
  } from "lucide-svelte";
  import {
    checkSecureElementSupport,
    deleteKey,
    generateSecureKey,
    listKeys,
    signWithKey,
    type AuthenticationMode,
    type SecureElementBacking,
  } from "tauri-plugin-secure-element-api";
  import testVectorsData from "./cross-platform-test-vectors.json";

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
  let testSectionExpanded = $state(false);

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
    testSectionExpanded = true;
    clearLog();

    const startTime = Date.now();
    const testKeyName = `test_key_${Date.now()}`;
    let testPublicKey = "";
    let passed = 0;
    let failed = 0;

    const tests: { name: string; fn: () => Promise<void> }[] = [
      {
        name: "Check Secure Element Support",
        fn: async () => {
          const result = await checkSecureElementSupport();
          if (typeof result.discrete !== "boolean") {
            throw new Error("Invalid response: missing discrete");
          }
          if (typeof result.integrated !== "boolean") {
            throw new Error("Invalid response: missing integrated");
          }
          if (typeof result.strongest !== "string") {
            throw new Error("Invalid response: missing strongest");
          }
          if (typeof result.emulated !== "boolean") {
            throw new Error("Invalid response: missing emulated");
          }
          log(
            `  Strongest: ${result.strongest}, Discrete: ${result.discrete}, Integrated: ${result.integrated}, Firmware: ${result.firmware}, Emulated: ${result.emulated}, Bio-Only: ${result.canEnforceBiometricOnly}`
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

          const signature = await signWithKey(testKeyName, dataBytes);
          if (!signature || signature.length === 0) {
            throw new Error("Empty signature returned");
          }

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

          const { publicKey } = await generateSecureKey(workflowKey, "none");
          log(`  Created: ${workflowKey}`);

          const encoder = new TextEncoder();
          const message = "workflow test message";
          const sig = await signWithKey(workflowKey, encoder.encode(message));
          log(`  Signed message (${sig.length} bytes)`);

          const isValid = await invoke<boolean>("verify_signature", {
            publicKeyBase64: publicKey,
            message: Array.from(encoder.encode(message)),
            signatureDer: Array.from(sig),
          });
          if (!isValid) throw new Error("Signature verification failed");
          log(`  Verified signature with p256 crate`);

          await deleteKey(workflowKey);
          log(`  Deleted: ${workflowKey}`);

          const keys = await listKeys(workflowKey);
          if (keys && keys.length > 0) throw new Error("Key not deleted");
          log(`  Verified key is deleted`);
        },
      },
      {
        name: "Verify Cross-Platform Signatures",
        fn: async () => {
          const vectors: TestVector[] = testVectorsData.vectors;
          if (vectors.length === 0) {
            log(
              `  Skipped: no vectors in cross-platform-test-vectors.json yet`
            );
            return;
          }

          const encoder = new TextEncoder();
          let verified = 0;

          for (const vec of vectors) {
            const messageBytes = Array.from(encoder.encode(vec.message));
            const sigBytes = Array.from(
              _base64ToUint8Array(vec.signatureBase64)
            );

            const isValid = await invoke<boolean>("verify_signature", {
              publicKeyBase64: vec.publicKey,
              message: messageBytes,
              signatureDer: sigBytes,
            });

            if (!isValid) {
              throw new Error(
                `Signature from ${vec.platform} failed: "${vec.label}"`
              );
            }
            verified++;
          }

          log(
            `  Verified ${verified} cross-platform signature(s) from: ${[...new Set(vectors.map((v) => v.platform))].join(", ")}`
          );
        },
      },
    ];

    testResults = tests.map((t) => ({
      name: t.name,
      status: "pending" as const,
    }));

    log("═══════════════════════════════════════");
    log("Starting Integration Tests");
    log("═══════════════════════════════════════");

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
    _refreshKeysList();
  }

  // Key Management
  let newKeyName = $state("");
  let createdKey = $state(null);
  let createKeyError = $state("");
  let showCreateForm = $state(false);
  let keysList = $state([]);
  let listKeysError = $state("");
  let authMode = $state<AuthenticationMode>("pinOrBiometric");

  // Sign & Verify
  let selectedKeyName = $state("");
  let messageToSign = $state("");
  let signature = $state<Uint8Array | null>(null);
  let signError = $state("");
  let verifyPublicKey = $state("");
  let verifyResult = $state<boolean | null>(null);
  let verifyError = $state("");
  let isVerifying = $state(false);

  // Hardware Support
  let emulated = $state<boolean | null>(null);
  let strongest = $state<SecureElementBacking | null>(null);
  let canEnforceBiometricOnly = $state<boolean | null>(null);
  let secureElementCheckError = $state("");

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
        showCreateForm = false;
        _refreshKeysList();
      })
      .catch((err) => {
        createKeyError = err.toString();
      });
  }

  function _refreshKeysList() {
    listKeysError = "";
    listKeys()
      .then((keys) => {
        keysList = keys;
      })
      .catch((err) => {
        listKeysError = err.toString();
      });
  }

  function _signMessage() {
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

  async function _verifySignature() {
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
        if (selectedKeyName === keyName) {
          selectedKeyName = "";
          signature = null;
        }
        _refreshKeysList();
      }
    } catch (err) {
      listKeysError = err instanceof Error ? err.message : String(err);
    }
  }

  async function _copyToClipboard(text: string) {
    try {
      await navigator.clipboard.writeText(text);
    } catch (err) {
      console.error("Failed to copy:", err);
    }
  }

  function _selectKey(keyName: string) {
    selectedKeyName = keyName;
    signature = null;
    verifyResult = null;
    signError = "";
    verifyError = "";
  }

  function formatSignature(sig: Uint8Array | null) {
    if (!sig) return "";
    return Array.from(sig)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  function _checkSecureElementSupport() {
    secureElementCheckError = "";
    checkSecureElementSupport()
      .then((result) => {
        emulated = result.emulated;
        strongest = result.strongest;
        canEnforceBiometricOnly = result.canEnforceBiometricOnly;
      })
      .catch((err) => {
        secureElementCheckError = err.toString();
        emulated = false;
        strongest = "none";
        canEnforceBiometricOnly = false;
      });
  }

  $effect(() => {
    if (authMode === "biometricOnly" && canEnforceBiometricOnly === false) {
      authMode = "pinOrBiometric";
    }
  });

  // Cross-Platform Test Vectors
  type TestVector = {
    platform: string;
    label: string;
    publicKey: string;
    message: string;
    signatureBase64: string;
    generatedAt: string;
  };

  type VectorVerifyResult = {
    label: string;
    platform: string;
    passed: boolean;
    error?: string;
  };

  let vectorSectionExpanded = $state(false);
  let isGeneratingVectors = $state(false);
  let generatedVectorsJson = $state("");
  let vectorGenerateError = $state("");
  let isVerifyingVectors = $state(false);
  let vectorVerifyResults = $state<VectorVerifyResult[]>([]);

  const TEST_MESSAGES = [
    "Hello, World!",
    "Test message for cross-platform verification",
    "\u3053\u3093\u306B\u3061\u306F\u4E16\u754C \uD83C\uDF0D",
    "a",
  ];

  function _uint8ArrayToBase64(bytes: Uint8Array): string {
    let binary = "";
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  function _base64ToUint8Array(base64: string): Uint8Array {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  async function _generateTestVectors() {
    if (isGeneratingVectors) return;
    isGeneratingVectors = true;
    generatedVectorsJson = "";
    vectorGenerateError = "";

    const keyName = `_xplat_testvec_${Date.now()}`;

    try {
      const currentPlatform = platform();
      const { publicKey } = await generateSecureKey(keyName, "none");
      const encoder = new TextEncoder();
      const vectors: TestVector[] = [];

      for (const message of TEST_MESSAGES) {
        const messageBytes = encoder.encode(message);
        const sig = await signWithKey(keyName, messageBytes);

        // Sanity check: verify locally before accepting
        const isValid = await invoke<boolean>("verify_signature", {
          publicKeyBase64: publicKey,
          message: Array.from(messageBytes),
          signatureDer: Array.from(sig),
        });

        if (!isValid) {
          throw new Error(
            `Sanity check failed: signature for "${message}" did not verify locally`
          );
        }

        vectors.push({
          platform: currentPlatform,
          label: `${currentPlatform} - ${message.length <= 20 ? message : message.substring(0, 20) + "..."}`,
          publicKey,
          message,
          signatureBase64: _uint8ArrayToBase64(sig),
          generatedAt: new Date().toISOString(),
        });
      }

      await deleteKey(keyName);
      generatedVectorsJson = JSON.stringify(vectors, null, 2);
    } catch (err) {
      vectorGenerateError = err instanceof Error ? err.message : String(err);
      // Clean up key on error
      try {
        await deleteKey(keyName);
      } catch {
        // ignore cleanup errors
      }
    } finally {
      isGeneratingVectors = false;
    }
  }

  async function _verifyTestVectors() {
    if (isVerifyingVectors) return;
    isVerifyingVectors = true;
    vectorVerifyResults = [];

    const vectors: TestVector[] = testVectorsData.vectors;
    if (vectors.length === 0) {
      vectorVerifyResults = [
        {
          label: "No test vectors",
          platform: "",
          passed: false,
          error: "No vectors in cross-platform-test-vectors.json yet",
        },
      ];
      isVerifyingVectors = false;
      return;
    }

    const encoder = new TextEncoder();
    const results: VectorVerifyResult[] = [];

    for (const vec of vectors) {
      try {
        const messageBytes = Array.from(encoder.encode(vec.message));
        const sigBytes = Array.from(_base64ToUint8Array(vec.signatureBase64));

        const isValid = await invoke<boolean>("verify_signature", {
          publicKeyBase64: vec.publicKey,
          message: messageBytes,
          signatureDer: sigBytes,
        });

        results.push({
          label: vec.label,
          platform: vec.platform,
          passed: isValid,
          error: isValid ? undefined : "Signature verification failed",
        });
      } catch (err) {
        results.push({
          label: vec.label,
          platform: vec.platform,
          passed: false,
          error: err instanceof Error ? err.message : String(err),
        });
      }
    }

    vectorVerifyResults = results;
    isVerifyingVectors = false;
  }

  async function _copyGeneratedVectors() {
    try {
      await navigator.clipboard.writeText(generatedVectorsJson);
    } catch (err) {
      console.error("Failed to copy:", err);
    }
  }

  // Initialize
  _refreshKeysList();
  _checkSecureElementSupport();
</script>

<main class="container py-3">
  <!-- Header with Hardware Status -->
  <div
    class="d-flex flex-column flex-md-row justify-content-between align-items-start align-items-md-center mb-4 pb-3 border-bottom"
  >
    <h1 class="h3 mb-2 mb-md-0">Secure Key Manager</h1>
    <div class="d-flex flex-wrap gap-2">
      {#if secureElementCheckError}
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
  </div>

  <div class="row g-4">
    <!-- Left Column: Keys -->
    <div class="col-12 col-lg-5">
      <section class="card h-100">
        <div
          class="card-header d-flex justify-content-between align-items-center"
        >
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
                  onkeydown={(e) => e.key === "Enter" && _createKey()}
                />
              </div>
              <div class="mb-2">
                <select
                  bind:value={authMode}
                  class="form-select form-select-sm"
                >
                  <option value="none">No Authentication</option>
                  <option value="pinOrBiometric">PIN or Biometric</option>
                  {#if canEnforceBiometricOnly === true}
                    <option value="biometricOnly">Biometric Only</option>
                  {/if}
                </select>
              </div>
              <button onclick={_createKey} class="btn btn-success btn-sm w-100">
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
              <span class="badge bg-info ms-1"
                >{createdKey.hardwareBacking}</span
              >
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
                        onclick={() => _selectKey(key.keyName)}
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
                        onclick={() => _copyToClipboard(key.publicKey)}
                        class="btn btn-outline-secondary btn-sm p-1"
                        title="Copy public key"
                      >
                        <Copy size={14} />
                      </button>
                      <button
                        onclick={() => _deleteKeyByName(key.keyName)}
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
    </div>

    <!-- Right Column: Sign & Verify -->
    <div class="col-12 col-lg-7">
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
              <label for="keySelect" class="form-label small fw-medium"
                >Select Key</label
              >
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
              <label for="message" class="form-label small fw-medium"
                >Message</label
              >
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
              onclick={_signMessage}
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
                  <div
                    class="d-flex justify-content-between align-items-center mb-1"
                  >
                    <span class="small fw-medium">Signature</span>
                    <button
                      onclick={() =>
                        _copyToClipboard(formatSignature(signature))}
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

                <button
                  onclick={_verifySignature}
                  class="btn btn-info btn-sm w-100"
                  disabled={isVerifying || !verifyPublicKey.trim()}
                >
                  {#if isVerifying}
                    <span class="spinner-border spinner-border-sm me-1"></span>
                    Verifying...
                  {:else}
                    Verify Signature
                  {/if}
                </button>

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
    </div>
  </div>

  <!-- Integration Tests (Collapsible) -->
  <section class="card mt-4">
    <div
      class="card-header d-flex justify-content-between align-items-center"
      style="cursor: pointer;"
      onclick={() => (testSectionExpanded = !testSectionExpanded)}
      onkeydown={(e) =>
        e.key === "Enter" && (testSectionExpanded = !testSectionExpanded)}
      role="button"
      tabindex="0"
    >
      <div class="d-flex align-items-center gap-2">
        <h2 class="h6 mb-0">Integration Tests</h2>
        {#if testSummary}
          <span
            class="badge {testSummary.failed === 0
              ? 'bg-success'
              : 'bg-danger'}"
          >
            {testSummary.passed}/{testSummary.total}
          </span>
        {/if}
      </div>
      {#if testSectionExpanded}
        <ChevronUp size={20} />
      {:else}
        <ChevronDown size={20} />
      {/if}
    </div>

    {#if testSectionExpanded}
      <div class="card-body">
        <div class="d-flex gap-2 mb-3">
          <button
            onclick={runAllTests}
            class="btn btn-primary btn-sm"
            disabled={isTestRunning}
          >
            {#if isTestRunning}
              <span class="spinner-border spinner-border-sm me-1"></span>
              Running...
            {:else}
              Run All Tests
            {/if}
          </button>
          <button
            onclick={clearLog}
            class="btn btn-outline-secondary btn-sm"
            disabled={isTestRunning}
          >
            Clear
          </button>
        </div>

        <!-- Test Status Badges -->
        {#if testResults.length > 0}
          <div class="d-flex flex-wrap gap-1 mb-3">
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
                style="font-size: 0.7rem;"
              >
                {test.status === "running"
                  ? "..."
                  : test.status === "passed"
                    ? "✓"
                    : test.status === "failed"
                      ? "✗"
                      : "○"}
              </span>
            {/each}
          </div>
        {/if}

        <!-- Console -->
        <div
          class="bg-dark text-light p-2 rounded font-monospace"
          style="height: 200px; overflow-y: auto; font-size: 0.75rem;"
        >
          {#if testLog.length === 0}
            <span class="text-muted">Click "Run All Tests" to start...</span>
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

        {#if testSummary}
          <div
            class="mt-2 small {testSummary.failed === 0
              ? 'text-success'
              : 'text-danger'}"
          >
            {testSummary.passed} passed, {testSummary.failed} failed in {testSummary.duration}ms
          </div>
        {/if}
      </div>
    {/if}
  </section>

  <!-- Cross-Platform Test Vectors (Collapsible) -->
  <section class="card mt-4">
    <div
      class="card-header d-flex justify-content-between align-items-center"
      style="cursor: pointer;"
      onclick={() => (vectorSectionExpanded = !vectorSectionExpanded)}
      onkeydown={(e) =>
        e.key === "Enter" && (vectorSectionExpanded = !vectorSectionExpanded)}
      role="button"
      tabindex="0"
    >
      <div class="d-flex align-items-center gap-2">
        <h2 class="h6 mb-0">Cross-Platform Test Vectors</h2>
        {#if vectorVerifyResults.length > 0}
          {@const allPassed = vectorVerifyResults.every((r) => r.passed)}
          <span class="badge {allPassed ? 'bg-success' : 'bg-danger'}">
            {vectorVerifyResults.filter((r) => r.passed)
              .length}/{vectorVerifyResults.length}
          </span>
        {/if}
      </div>
      {#if vectorSectionExpanded}
        <ChevronUp size={20} />
      {:else}
        <ChevronDown size={20} />
      {/if}
    </div>

    {#if vectorSectionExpanded}
      <div class="card-body">
        <!-- Generator -->
        <div class="mb-4">
          <h3 class="h6">Generate Vectors</h3>
          <p class="text-muted small mb-2">
            Creates signed test vectors for the current platform. Copy the
            output into <code>cross-platform-test-vectors.json</code>.
          </p>
          <button
            onclick={_generateTestVectors}
            class="btn btn-primary btn-sm"
            disabled={isGeneratingVectors}
          >
            {#if isGeneratingVectors}
              <span class="spinner-border spinner-border-sm me-1"></span>
              Generating...
            {:else}
              Generate Test Vectors
            {/if}
          </button>

          {#if vectorGenerateError}
            <div class="alert alert-danger mt-2 py-2 small">
              {vectorGenerateError}
            </div>
          {/if}

          {#if generatedVectorsJson}
            <div class="mt-2">
              <div class="d-flex gap-2 mb-1">
                <button
                  onclick={_copyGeneratedVectors}
                  class="btn btn-outline-secondary btn-sm"
                >
                  <Copy size={14} class="me-1" />
                  Copy JSON
                </button>
              </div>
              <textarea
                class="form-control font-monospace"
                style="font-size: 0.7rem; height: 200px;"
                readonly
                value={generatedVectorsJson}
              ></textarea>
            </div>
          {/if}
        </div>

        <hr />

        <!-- Verifier -->
        <div>
          <h3 class="h6">Verify Stored Vectors</h3>
          <p class="text-muted small mb-2">
            Verifies all signatures from <code
              >cross-platform-test-vectors.json</code
            >
            ({testVectorsData.vectors.length} vector{testVectorsData.vectors
              .length !== 1
              ? "s"
              : ""} loaded).
          </p>
          <button
            onclick={_verifyTestVectors}
            class="btn btn-primary btn-sm"
            disabled={isVerifyingVectors ||
              testVectorsData.vectors.length === 0}
          >
            {#if isVerifyingVectors}
              <span class="spinner-border spinner-border-sm me-1"></span>
              Verifying...
            {:else}
              Verify Cross-Platform Vectors
            {/if}
          </button>

          {#if vectorVerifyResults.length > 0}
            <div class="mt-2">
              {#each vectorVerifyResults as result}
                <div
                  class="d-flex align-items-center gap-2 py-1 border-bottom"
                  style="font-size: 0.8rem;"
                >
                  <span
                    class="badge {result.passed ? 'bg-success' : 'bg-danger'}"
                    style="font-size: 0.7rem;"
                  >
                    {result.passed ? "✓" : "✗"}
                  </span>
                  {#if result.platform}
                    <span
                      class="badge bg-secondary"
                      style="font-size: 0.65rem;"
                    >
                      {result.platform}
                    </span>
                  {/if}
                  <span>{result.label}</span>
                  {#if result.error}
                    <span class="text-danger small">({result.error})</span>
                  {/if}
                </div>
              {/each}
              <div
                class="mt-2 small {vectorVerifyResults.filter((r) => r.passed)
                  .length === vectorVerifyResults.length
                  ? 'text-success'
                  : 'text-danger'}"
              >
                {vectorVerifyResults.filter((r) => r.passed).length} passed, {vectorVerifyResults.filter(
                  (r) => !r.passed
                ).length} failed
              </div>
            </div>
          {/if}
        </div>
      </div>
    {/if}
  </section>
</main>

<style>
  .min-width-0 {
    min-width: 0;
  }
</style>
