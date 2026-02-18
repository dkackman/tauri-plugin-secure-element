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
  import CollapsibleCard from "./CollapsibleCard.svelte";
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

  let sectionExpanded = $state(false);
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

<CollapsibleCard
  title="Cross-Platform Test Vectors"
  bind:expanded={sectionExpanded}
>
  {#snippet badge()}
    {#if vectorVerifyResults.length > 0}
      {@const allPassed = vectorVerifyResults.every((r) => r.passed)}
      <span class="badge {allPassed ? 'bg-success' : 'bg-danger'}">
        {vectorVerifyResults.filter((r) => r.passed)
          .length}/{vectorVerifyResults.length}
      </span>
    {/if}
  {/snippet}

  <!-- Generator -->
  <div class="mb-4">
    <h3 class="h6">Generate Vectors</h3>
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
    <h3 class="h6">Verify Stored Vectors</h3>
    <p class="text-muted small mb-2">
      Verifies all signatures from <code>cross-platform-test-vectors.json</code>
      ({testVectorsData.vectors.length} vector{testVectorsData.vectors
        .length !== 1
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
</CollapsibleCard>
