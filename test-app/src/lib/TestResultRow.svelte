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
      <span
        class="spinner-border spinner-border-sm text-warning"
        style="width: 0.85rem; height: 0.85rem;"
      ></span>
    {:else if test.status === "passed"}
      <span class="text-success fw-bold">✓</span>
    {:else if test.status === "failed"}
      <span class="text-danger fw-bold">✗</span>
    {:else}
      <span class="text-muted">○</span>
    {/if}
  </td>
  <td title={test.message ?? ""}>{test.name}</td>
  <td
    class="text-end font-monospace text-muted"
    style="width: 6rem; font-size: 0.8rem;"
  >
    {#if test.duration !== undefined}
      {test.duration}ms
    {:else}
      —
    {/if}
  </td>
</tr>
