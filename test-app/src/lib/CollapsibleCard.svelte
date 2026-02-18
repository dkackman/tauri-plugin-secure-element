<script lang="ts">
  import { ChevronDown, ChevronUp } from "lucide-svelte";
  import type { Snippet } from "svelte";

  let {
    title,
    expanded = $bindable(false),
    badge,
    children,
  }: {
    title: string;
    expanded?: boolean;
    badge?: Snippet;
    children: Snippet;
  } = $props();
</script>

<section class="card mt-4">
  <div
    class="card-header d-flex justify-content-between align-items-center"
    style="cursor: pointer;"
    onclick={() => (expanded = !expanded)}
    onkeydown={(e) => e.key === "Enter" && (expanded = !expanded)}
    role="button"
    tabindex="0"
  >
    <div class="d-flex align-items-center gap-2">
      <h2 class="h6 mb-0">{title}</h2>
      {@render badge?.()}
    </div>
    {#if expanded}
      <ChevronUp size={20} />
    {:else}
      <ChevronDown size={20} />
    {/if}
  </div>

  {#if expanded}
    <div class="card-body">
      {@render children()}
    </div>
  {/if}
</section>
