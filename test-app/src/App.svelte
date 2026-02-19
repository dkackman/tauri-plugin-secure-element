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
