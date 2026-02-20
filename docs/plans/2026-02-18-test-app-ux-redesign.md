# Test App UX Redesign Design

**Date:** 2026-02-18
**Status:** Approved

## Problem

The integration tests are buried in a collapsible section at the bottom of the page. Since running tests repeatedly is the primary developer workflow, this creates unnecessary friction: scroll down + expand + run on every session.

## Solution

Reorganize the app into a **tests-first tab layout** using Bootstrap NavTabs. Integration Tests become the default first tab, making them one click away at all times.

## Design

### Shell (always visible)

Single header row with title and hardware status badges inline:

```
Secure Key Manager  •  [Discrete] [Integrated] [Not Emulated]
──────────────────────────────────────────────────────────────
[Integration Tests]  [Keys & Sign]  [Test Vectors]
```

- `HardwareStatus` badges move into the header title row (flex layout)
- Bootstrap `.nav-tabs` below the header
- Active tab managed by `activeTab: 'tests' | 'keys' | 'vectors'` state in `App.svelte`
- Default tab: `'tests'`
- Tab switching resets tab-local state (no cross-tab persistence needed)

### Tab 1: Integration Tests (default)

```
[▶ Run All Tests]    ■ 11 passed  ■ 0 failed  (4.2s)
────────────────────────────────────────────────────
✓  Check Secure Element Support         12ms
✓  Generate Key (none auth)             341ms
✓  List Keys by name                    88ms
✗  Sign message                         ERROR
○  Verify signature (pending)           —
...
────────────────────────────────────────────────────
Console (flex-grow fills remaining viewport)
[12:34:01] ✓ checkSecureElementSupport: passed (12ms)
[12:34:01] ✗ signMessage: Error: key not found
...
```

- **Run All Tests** is a large primary button — the hero action
- **Summary row** shows pass count, fail count, and total elapsed time
- **Test result table**: 11 rows, each with test name, status icon (✓/✗/spinner/○), duration
- **Console log** uses `flex-grow: 1` to fill remaining viewport height (no fixed cap)
- Remove `CollapsibleCard` wrapper from `IntegrationTests.svelte`
- Add new `TestResultRow.svelte` component for individual test rows

### Tab 2: Keys & Sign

Two-column layout identical to current (col-lg-5 KeyManager + col-lg-7 SignVerify). No functional changes — gains breathing room from not competing with test sections on the same page.

### Tab 3: Test Vectors

Current `TestVectors.svelte` content promoted to a full tab. Remove `CollapsibleCard` wrapper. No functional changes.

## Component Changes

| Component | Change |
|-----------|--------|
| `App.svelte` | Add `activeTab` state; render Bootstrap NavTabs; conditionally render tab content |
| `HardwareStatus.svelte` | Render inline in header title row (flex, no card wrapper needed) |
| `IntegrationTests.svelte` | Remove `CollapsibleCard`; restructure layout to summary row + test table + flex console |
| `TestVectors.svelte` | Remove `CollapsibleCard`; render as full tab content |
| `CollapsibleCard.svelte` | No longer used; can be removed |
| New: `TestResultRow.svelte` | Renders one test row: name + status badge + duration |

## Non-Goals

- No routing library — single `activeTab` state variable is sufficient
- No individual test run buttons — run-all is sufficient
- No keyboard shortcuts — not requested
- No cross-tab state persistence — reset is acceptable
- No changes to the plugin API or Rust/Swift/Kotlin code
