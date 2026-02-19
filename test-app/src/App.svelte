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
  <div class="d-flex flex-column flex-md-row justify-content-between align-items-start align-items-md-center mb-3 pb-2 border-bottom">
    <h1 class="h4 mb-0">Secure Key Manager</h1>
    <HardwareStatus
      {strongest}
      {emulated}
      {canEnforceBiometricOnly}
      error={secureElementCheckError}
    />
  </div>

  <!-- Tab navigation -->
  <ul class="nav nav-tabs nav-fill mb-3" role="tablist">
    <li class="nav-item" role="presentation">
      <button
        id="tab-tests"
        type="button"
        class="nav-link {activeTab === 'tests' ? 'active' : ''}"
        role="tab"
        aria-selected={activeTab === "tests"}
        aria-controls="panel-tests"
        tabindex={activeTab === "tests" ? 0 : -1}
        onclick={() => (activeTab = "tests")}
      >
        Tests
      </button>
    </li>
    <li class="nav-item" role="presentation">
      <button
        id="tab-keys"
        type="button"
        class="nav-link {activeTab === 'keys' ? 'active' : ''}"
        role="tab"
        aria-selected={activeTab === "keys"}
        aria-controls="panel-keys"
        tabindex={activeTab === "keys" ? 0 : -1}
        onclick={() => (activeTab = "keys")}
      >
        Keys &amp; Sign
      </button>
    </li>
    <li class="nav-item" role="presentation">
      <button
        id="tab-vectors"
        type="button"
        class="nav-link {activeTab === 'vectors' ? 'active' : ''}"
        role="tab"
        aria-selected={activeTab === "vectors"}
        aria-controls="panel-vectors"
        tabindex={activeTab === "vectors" ? 0 : -1}
        onclick={() => (activeTab = "vectors")}
      >
        Vectors
      </button>
    </li>
  </ul>

  <!-- Tab content -->
  {#if activeTab === "tests"}
    <div id="panel-tests" role="tabpanel" aria-labelledby="tab-tests" tabindex="0">
      <IntegrationTests onComplete={refreshKeysList} />
    </div>
  {:else if activeTab === "keys"}
    <div id="panel-keys" role="tabpanel" aria-labelledby="tab-keys" tabindex="0">
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
    </div>
  {:else if activeTab === "vectors"}
    <div id="panel-vectors" role="tabpanel" aria-labelledby="tab-vectors" tabindex="0">
      <TestVectors />
    </div>
  {/if}
</main>
