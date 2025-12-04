<script>
  import { generateSecureKey, ping, signWithKey } from 'tauri-plugin-secure-element-api';

	let response = $state('')
	let signInput = $state('')

	function updateResponse(returnValue) {
		response += `[${new Date().toLocaleTimeString()}] ` + (typeof returnValue === 'string' ? returnValue : JSON.stringify(returnValue)) + '<br>'
	}

	function _ping() {
		ping("Pong!").then(updateResponse).catch(updateResponse)
	}

	function _generateSecureKey() {
		generateSecureKey(32).then(updateResponse).catch(updateResponse)
	}

	function _signWithKey() {
		if (!signInput.trim()) {
			updateResponse('Error: Please enter data to sign')
			return
		}
		signWithKey(signInput)
			.then((signature) => {
				// Convert Uint8Array to hex string for display
				const hex = Array.from(signature)
					.map(b => b.toString(16).padStart(2, '0'))
					.join('')
				updateResponse(`Signature: ${hex}`)
			})
			.catch(updateResponse)
	}
</script>

<main class="container">
  <h1>Secure Element Example</h1>

  <div class="row">
    <button onclick="{_ping}">Ping</button>
  </div>
  <div class="row">
    <button onclick="{_generateSecureKey}">Generate Secure Key</button>
  </div>
  <div class="row">
    <input type="text" bind:value={signInput} placeholder="Enter data to sign" />
    <button onclick="{_signWithKey}">Sign with Key</button>
  </div>
  <div class="row">
    <div>{@html response}</div>
  </div>

</main>

<style>
  .logo.vite:hover {
    filter: drop-shadow(0 0 2em #747bff);
  }

  .logo.svelte:hover {
    filter: drop-shadow(0 0 2em #ff3e00);
  }
</style>
