# Test App UX Redesign Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Reorganize the test-app into a tests-first tab layout so integration tests are one click away instead of buried in a collapsible section.

**Architecture:** Replace the single-page scroll layout with Bootstrap NavTabs in `App.svelte`. The header collapses title + hardware status into one line. `IntegrationTests` becomes a full-screen flex layout (run button → test table → growing console). `TestVectors` and the key/sign UI become secondary tabs. `CollapsibleCard` is deleted.

**Tech Stack:** Svelte 5 (runes), Bootstrap 5.3.8, lucide-svelte, TypeScript

---

### Task 1: Add tab state and NavTabs shell to App.svelte

**Files:**
- Modify: `test-app/src/App.svelte`

This is the structural change. We add one state variable (`activeTab`), collapse the header into a single flex row, and add Bootstrap NavTabs. Each tab conditionally renders its content.

**Step 1: Replace App.svelte with the tab-based version**

Replace the entire file content with:

```svelte
<script lang="ts">
  import {
    checkSecureElementSupport,
    listKeys,
    type KeyInfo,
    type SecureElementBacking,
  } from "tauri-plugin-secure-element-api";
  import HardwareStatus from "./lib/HardwareStatus.svelte";
  import IntegrationTests from "./lib/IntegrationTests.svelte";
  import KeyManager from "./lib/KeyManager.svelte";
  import SignVerify from "./lib/SignVerify.svelte";
  import TestVectors from "./lib/TestVectors.svelte";

  // Tab state
  let activeTab = $state<"tests" | "keys" | "vectors">("tests");

  // Hardware support state
  let emulated = $state<boolean | null>(null);
  let strongest = $state<SecureElementBacking | null>(null);
  let canEnforceBiometricOnly = $state<boolean | null>(null);
  let secureElementCheckError = $state("");

  // Shared key state (passed to KeyManager for display and to SignVerify for signing)
  let keysList = $state<KeyInfo[]>([]);
  let listKeysError = $state("");
  let selectedKeyName = $state("");

  function refreshKeysList() {
    listKeysError = "";
    listKeys()
      .then((keys) => {
        keysList = keys;
      })
      .catch((err) => {
        listKeysError = err.toString();
      });
  }

  function checkHardware() {
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

  refreshKeysList();
  checkHardware();
</script>

<main class="container py-3">
  <!-- Header: title + hardware status on one line -->
  <div class="d-flex justify-content-between align-items-center mb-3 pb-2 border-bottom">
    <h1 class="h4 mb-0">Secure Key Manager</h1>
    <HardwareStatus
      {strongest}
      {emulated}
      {canEnforceBiometricOnly}
      error={secureElementCheckError}
    />
  </div>

  <!-- Tab navigation -->
  <ul class="nav nav-tabs mb-3">
    <li class="nav-item">
      <button
        class="nav-link {activeTab === 'tests' ? 'active' : ''}"
        onclick={() => (activeTab = "tests")}
      >
        Integration Tests
      </button>
    </li>
    <li class="nav-item">
      <button
        class="nav-link {activeTab === 'keys' ? 'active' : ''}"
        onclick={() => (activeTab = "keys")}
      >
        Keys &amp; Sign
      </button>
    </li>
    <li class="nav-item">
      <button
        class="nav-link {activeTab === 'vectors' ? 'active' : ''}"
        onclick={() => (activeTab = "vectors")}
      >
        Test Vectors
      </button>
    </li>
  </ul>

  <!-- Tab content -->
  {#if activeTab === "tests"}
    <IntegrationTests onComplete={refreshKeysList} />
  {:else if activeTab === "keys"}
    <div class="row g-4">
      <div class="col-12 col-lg-5">
        <KeyManager
          {keysList}
          {listKeysError}
          bind:selectedKeyName
          {canEnforceBiometricOnly}
          onRefreshKeys={refreshKeysList}
          onDeleteError={(msg) => (listKeysError = msg)}
        />
      </div>
      <div class="col-12 col-lg-7">
        <SignVerify {keysList} bind:selectedKeyName />
      </div>
    </div>
  {:else if activeTab === "vectors"}
    <TestVectors />
  {/if}
</main>
```

**Step 2: Verify the app compiles**

Run from `test-app/`:
```bash
pnpm build
```
Expected: Build succeeds. (The app may show the Tests tab with the old collapsible card still visible — that's fine, we fix it in Task 2.)

**Step 3: Commit**

```bash
git add test-app/src/App.svelte
git commit -m "feat: add tab navigation to test-app (tests-first)"
```

---

### Task 2: Create TestResultRow.svelte

**Files:**
- Create: `test-app/src/lib/TestResultRow.svelte`

This small component renders a single row in the test results table. Extracting it keeps `IntegrationTests.svelte` readable.

**Step 1: Create the file**

```svelte
<script lang="ts">
  let {
    test,
  }: {
    test: {
      name: string;
      status: "pending" | "running" | "passed" | "failed";
      duration?: number;
      message?: string;
    };
  } = $props();
</script>

<tr>
  <td class="text-center" style="width: 2rem;">
    {#if test.status === "running"}
      <span class="spinner-border spinner-border-sm text-warning" style="width: 0.85rem; height: 0.85rem;"></span>
    {:else if test.status === "passed"}
      <span class="text-success fw-bold">✓</span>
    {:else if test.status === "failed"}
      <span class="text-danger fw-bold">✗</span>
    {:else}
      <span class="text-muted">○</span>
    {/if}
  </td>
  <td title={test.message ?? ""}>{test.name}</td>
  <td class="text-end font-monospace text-muted" style="width: 6rem; font-size: 0.8rem;">
    {#if test.duration !== undefined}
      {test.duration}ms
    {:else}
      —
    {/if}
  </td>
</tr>
```

**Step 2: Commit**

```bash
git add test-app/src/lib/TestResultRow.svelte
git commit -m "feat: add TestResultRow component for test result table"
```

---

### Task 3: Restructure IntegrationTests.svelte

**Files:**
- Modify: `test-app/src/lib/IntegrationTests.svelte`

Remove the `CollapsibleCard` wrapper. Replace the badge grid + fixed-height console with: action row → test result table → full-height flex console. The test logic (all the `runTest`, `runAllTests`, etc.) is unchanged — only the template and the removal of `CollapsibleCard`/`sectionExpanded` change.

**Step 1: Replace the file**

Replace the entire `IntegrationTests.svelte` with:

```svelte
<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import {
    checkSecureElementSupport,
    deleteKey,
    generateSecureKey,
    listKeys,
    signWithKey,
  } from "tauri-plugin-secure-element-api";
  import testVectorsData from "../cross-platform-test-vectors.json";
  import SpinnerButton from "./SpinnerButton.svelte";
  import TestResultRow from "./TestResultRow.svelte";
  import { base64ToUint8Array } from "./utils.js";

  let { onComplete }: { onComplete: () => void } = $props();

  type TestResult = {
    name: string;
    status: "pending" | "running" | "passed" | "failed";
    message?: string;
    duration?: number;
  };

  type TestVector = {
    platform: string;
    label: string;
    publicKey: string;
    message: string;
    signatureBase64: string;
    generatedAt: string;
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

          const isValid = await invoke<boolean>("verify_signature", {
            publicKeyBase64: testPublicKey,
            message: Array.from(dataBytes),
            signatureDer: Array.from(signature),
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
              base64ToUint8Array(vec.signatureBase64)
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
    onComplete();
  }
</script>

<!-- Full-height flex layout: action row → test table → growing console -->
<div class="d-flex flex-column" style="height: calc(100vh - 180px);">
  <!-- Action row -->
  <div class="d-flex align-items-center gap-3 mb-3 flex-shrink-0">
    <SpinnerButton
      loading={isTestRunning}
      label="Run All Tests"
      loadingLabel="Running..."
      onclick={runAllTests}
      class="btn btn-primary"
    />
    <button
      onclick={clearLog}
      class="btn btn-outline-secondary btn-sm"
      disabled={isTestRunning}
    >
      Clear
    </button>
    {#if testSummary}
      <div class="d-flex gap-2 ms-auto align-items-center">
        <span class="badge bg-success">{testSummary.passed} passed</span>
        {#if testSummary.failed > 0}
          <span class="badge bg-danger">{testSummary.failed} failed</span>
        {/if}
        <span class="text-muted small">{testSummary.duration}ms</span>
      </div>
    {/if}
  </div>

  <!-- Test result table -->
  {#if testResults.length > 0}
    <div class="mb-3 flex-shrink-0">
      <table class="table table-sm table-hover mb-0" style="font-size: 0.85rem;">
        <tbody>
          {#each testResults as test}
            <TestResultRow {test} />
          {/each}
        </tbody>
      </table>
    </div>
  {/if}

  <!-- Console: fills remaining height -->
  <div
    class="bg-dark text-light p-2 rounded font-monospace flex-grow-1 overflow-auto"
    style="min-height: 0; font-size: 0.75rem;"
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
</div>
```

**Step 2: Build to verify**

```bash
cd test-app && pnpm build
```
Expected: Build succeeds. No TypeScript errors.

**Step 3: Commit**

```bash
git add test-app/src/lib/IntegrationTests.svelte
git commit -m "feat: restructure IntegrationTests as full-page tab with flex console"
```

---

### Task 4: Restructure TestVectors.svelte

**Files:**
- Modify: `test-app/src/lib/TestVectors.svelte`

Remove `CollapsibleCard` wrapper and `sectionExpanded` state. All logic unchanged. The template is the same content that was inside the `CollapsibleCard`'s body — just promoted to the top level.

**Step 1: Replace the file**

```svelte
<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { platform } from "@tauri-apps/plugin-os";
  import { Copy } from "lucide-svelte";
  import {
    deleteKey,
    generateSecureKey,
    signWithKey,
  } from "tauri-plugin-secure-element-api";
  import testVectorsData from "../cross-platform-test-vectors.json";
  import SpinnerButton from "./SpinnerButton.svelte";
  import {
    base64ToUint8Array,
    copyToClipboard,
    uint8ArrayToBase64,
  } from "./utils.js";

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

  const TEST_MESSAGES = [
    "Hello, World!",
    "Test message for cross-platform verification",
    "\u3053\u3093\u306B\u3061\u306F\u4E16\u754C \uD83C\uDF0D",
    "a",
  ];

  let isGeneratingVectors = $state(false);
  let generatedVectorsJson = $state("");
  let vectorGenerateError = $state("");
  let isVerifyingVectors = $state(false);
  let vectorVerifyResults = $state<VectorVerifyResult[]>([]);

  async function generateTestVectors() {
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
          signatureBase64: uint8ArrayToBase64(sig),
          generatedAt: new Date().toISOString(),
        });
      }

      await deleteKey(keyName);
      generatedVectorsJson = JSON.stringify(vectors, null, 2);
    } catch (err) {
      vectorGenerateError = err instanceof Error ? err.message : String(err);
      try {
        await deleteKey(keyName);
      } catch {
        // ignore cleanup errors
      }
    } finally {
      isGeneratingVectors = false;
    }
  }

  async function verifyTestVectors() {
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
        const sigBytes = Array.from(base64ToUint8Array(vec.signatureBase64));

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
</script>

<!-- Generator -->
<div class="mb-4">
  <h2 class="h6">Generate Vectors</h2>
  <p class="text-muted small mb-2">
    Creates signed test vectors for the current platform. Copy the output into <code
      >cross-platform-test-vectors.json</code
    >.
  </p>
  <SpinnerButton
    loading={isGeneratingVectors}
    label="Generate Test Vectors"
    loadingLabel="Generating..."
    onclick={generateTestVectors}
  />

  {#if vectorGenerateError}
    <div class="alert alert-danger mt-2 py-2 small">
      {vectorGenerateError}
    </div>
  {/if}

  {#if generatedVectorsJson}
    <div class="mt-2">
      <div class="d-flex gap-2 mb-1">
        <button
          onclick={() => copyToClipboard(generatedVectorsJson)}
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
  <h2 class="h6">Verify Stored Vectors</h2>
  <p class="text-muted small mb-2">
    Verifies all signatures from <code>cross-platform-test-vectors.json</code>
    ({testVectorsData.vectors.length} vector{testVectorsData.vectors.length !== 1
      ? "s"
      : ""} loaded).
  </p>
  <SpinnerButton
    loading={isVerifyingVectors}
    disabled={testVectorsData.vectors.length === 0}
    label="Verify Cross-Platform Vectors"
    loadingLabel="Verifying..."
    onclick={verifyTestVectors}
  />

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
            <span class="badge bg-secondary" style="font-size: 0.65rem;">
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
        class="mt-2 small {vectorVerifyResults.filter((r) => r.passed).length ===
        vectorVerifyResults.length
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
```

**Step 2: Build to verify**

```bash
cd test-app && pnpm build
```
Expected: Build succeeds.

**Step 3: Commit**

```bash
git add test-app/src/lib/TestVectors.svelte
git commit -m "feat: promote TestVectors to full tab content"
```

---

### Task 5: Delete CollapsibleCard.svelte

**Files:**
- Delete: `test-app/src/lib/CollapsibleCard.svelte`

`CollapsibleCard` is no longer imported by anything. Remove it to avoid dead code.

**Step 1: Verify it has no remaining imports**

```bash
grep -r "CollapsibleCard" test-app/src/
```
Expected: No output. If any file still imports it, fix that file first before deleting.

**Step 2: Delete the file**

```bash
rm test-app/src/lib/CollapsibleCard.svelte
```

**Step 3: Build one final time**

```bash
cd test-app && pnpm build
```
Expected: Build succeeds with no references to `CollapsibleCard`.

**Step 4: Commit**

```bash
git add -u test-app/src/lib/CollapsibleCard.svelte
git commit -m "chore: remove CollapsibleCard (no longer used after tab refactor)"
```

---

## Verification Checklist

After all tasks are complete, manually verify in the running app:

- [ ] App opens to Integration Tests tab by default
- [ ] Header shows title and hardware badges on one line
- [ ] "Run All Tests" button is immediately visible without scrolling
- [ ] Running tests shows a spinner per row, then ✓/✗ with duration
- [ ] Console fills remaining screen height and scrolls independently
- [ ] Summary row (X passed / Y failed / Zms) appears after run
- [ ] Clear button resets table and console
- [ ] Switching to "Keys & Sign" tab shows KeyManager + SignVerify
- [ ] Switching to "Test Vectors" tab shows vector generator/verifier
- [ ] Hardware badges update correctly (Checking... → actual values)
