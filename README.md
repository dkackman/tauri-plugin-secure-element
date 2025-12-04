# Tauri Plugin Secure Element

A Tauri plugin for secure element functionality.

## Prerequisites

- [Rust](https://www.rust-lang.org/) (latest stable version)
- [Node.js](https://nodejs.org/) (version 20.19+ or 22.12+)
- [pnpm](https://pnpm.io/) (package manager)
- [Tauri CLI](https://tauri.app/v1/guides/getting-started/prerequisites) (installed via pnpm)

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
cd tauri-plugin-secure-element
pnpm build
cd test-app
pnpm build
```

Or use the VS Code task "build-all" to build everything in sequence.

## Running

### Run the Example App in Development Mode

```bash
cd test-app
pnpm tauri dev
```

This will:

1. Build the plugin (via prebuild script)
2. Start the Vite dev server
3. Launch the Tauri application

### Run the Example App (Production Build)

```bash
cd test-app
pnpm tauri build
```

This creates a production build of the application.

## Project Structure

```bash
tauri-plugin-secure-element/
├── src/              # Rust plugin source code
├── guest-js/         # TypeScript guest JavaScript code
├── dist-js/          # Built JavaScript files (generated)
├── examples/
│   └── test-app/     # Test Tauri application
│       ├── src/      # Frontend source (Svelte)
│       └── src-tauri/ # Tauri Rust application
└── package.json      # Plugin package configuration
```

## Development

This project uses a pnpm workspace. The plugin and example app are both part of the workspace:

- **Plugin**: `tauri-plugin-secure-element/`
- **Test App**: `test-app/`

### Making Changes

1. Edit the Rust plugin code in `src/`
2. Edit the TypeScript guest code in `guest-js/`
3. Rebuild the plugin: `pnpm build`
4. The example app will automatically use the updated plugin
