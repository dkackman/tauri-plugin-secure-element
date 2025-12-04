<script>
  import { ping } from 'tauri-plugin-secure-element-api';

	let response = $state('')

	function updateResponse(returnValue) {
		response += `[${new Date().toLocaleTimeString()}] ` + (typeof returnValue === 'string' ? returnValue : JSON.stringify(returnValue)) + '<br>'
	}

	function _ping() {
		ping("Pong!").then(updateResponse).catch(updateResponse)
	}
</script>

<main class="container">
  <h1>Secure Element Example</h1>

  <div class="row">
    <button onclick="{_ping}">Ping</button>
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
