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
  <!-- Header with Hardware Status -->
  <div
    class="d-flex flex-column flex-md-row justify-content-between align-items-start align-items-md-center mb-4 pb-3 border-bottom"
  >
    <h1 class="h3 mb-2 mb-md-0">Secure Key Manager</h1>
    <HardwareStatus
      {strongest}
      {emulated}
      {canEnforceBiometricOnly}
      error={secureElementCheckError}
    />
  </div>

  <div class="row g-4">
    <!-- Left Column: Keys -->
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

    <!-- Right Column: Sign & Verify -->
    <div class="col-12 col-lg-7">
      <SignVerify {keysList} bind:selectedKeyName />
    </div>
  </div>

  <IntegrationTests onComplete={refreshKeysList} />
  <TestVectors />
</main>
