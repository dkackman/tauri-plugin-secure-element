<script lang="ts">
  let {
    loading,
    disabled = false,
    label,
    loadingLabel,
    onclick,
    class: cls = "btn btn-primary btn-sm",
  }: {
    loading: boolean;
    disabled?: boolean;
    label: string;
    loadingLabel: string;
    onclick: () => void;
    class?: string;
  } = $props();
</script>

<button {onclick} class={cls} disabled={loading || disabled}>
  {#if loading}
    <span class="spinner-border spinner-border-sm me-1"></span>
    {loadingLabel}
  {:else}
    {label}
  {/if}
</button>
