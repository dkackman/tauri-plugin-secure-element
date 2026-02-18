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
  import CollapsibleCard from "./CollapsibleCard.svelte";
  import SpinnerButton from "./SpinnerButton.svelte";
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
  let sectionExpanded = $state(false);

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
    sectionExpanded = true;
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

<CollapsibleCard title="Integration Tests" bind:expanded={sectionExpanded}>
  {#snippet badge()}
    {#if testSummary}
      <span
        class="badge {testSummary.failed === 0 ? 'bg-success' : 'bg-danger'}"
      >
        {testSummary.passed}/{testSummary.total}
      </span>
    {/if}
  {/snippet}

  <div class="d-flex gap-2 mb-3">
    <SpinnerButton
      loading={isTestRunning}
      label="Run All Tests"
      loadingLabel="Running..."
      onclick={runAllTests}
    />
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
</CollapsibleCard>
