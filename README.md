# Tauri Plugin Secure Element

A Tauri plugin for secure element functionality.

## Prerequisites

- [Rust](https://www.rust-lang.org/) (latest stable version)
- [Node.js](https://nodejs.org/) (version 20.19+ or 22.12+)
- [pnpm](https://pnpm.io/) (package manager)
- [Tauri CLI](https://tauri.app/v1/guides/getting-started/prerequisites) (installed via pnpm)
- [Setup system dependencies for Tauri](https://v2.tauri.app/start/prerequisites/)

## Installation

- Install dependencies:

```bash
pnpm install
```

## Building

### Build the Plugin

Build the Rust plugin and JavaScript bindings:

```bash
cd tauri-plugin-secure-element
pnpm build
```

This will:

- Compile the Rust plugin code
- Build the TypeScript guest JavaScript code into `dist-js/`

### Build the Example App

Build the example Tauri application:

```bash
cd test-app
pnpm build
```

The example app's `prebuild` script will automatically build the plugin first.

### Build Everything

From the plugin root directory:

```bash
pnpm build
```

Or use the VS Code task "build-all" to build everything in sequence.

## Running

### Run the Test App in Development Mode

```bash
cd test-app
pnpm tauri ios dev

or

pnpm tauri android dev
```
