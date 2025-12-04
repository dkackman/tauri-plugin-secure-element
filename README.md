# Tauri Plugin tauri-plugin-secure-element

A Tauri plugin for secure element functionality.

## Prerequisites

- [Rust](https://www.rust-lang.org/) (latest stable version)
- [Node.js](https://nodejs.org/) (v18 or later)
- [pnpm](https://pnpm.io/) (package manager)
- [Tauri CLI](https://tauri.app/v1/guides/getting-started/prerequisites) (installed globally or via project dependencies)

## Project Structure

This is a pnpm workspace containing:

- `tauri-plugin-secure-element/` - The main plugin directory
  - `guest-js/` - TypeScript guest bindings
  - `dist-js/` - Bundled JavaScript output
  - `src/` - Rust plugin source code
- `test-app/` - Test application for development and testing

## Building the Plugin

### 1. Install Dependencies

From the project root, install all workspace dependencies:

```bash
pnpm install
```

### 2. Build JavaScript/TypeScript Components

The plugin has two JavaScript build steps:

**Build guest-js (TypeScript compilation):**

```bash
cd tauri-plugin-secure-element/guest-js
pnpm build
```

**Build dist-js (Rollup bundling):**

```bash
cd tauri-plugin-secure-element
pnpm build
```

Or build both from the plugin directory:

```bash
cd tauri-plugin-secure-element
cd guest-js && pnpm build && cd .. && pnpm build
```

### 3. Rust Build

The Rust code will be built automatically when you build or run the test app. However, you can also build it directly:

```bash
cd tauri-plugin-secure-element
cargo build
```

## Running the Test App

The test app is located in the `test-app/` directory and uses the plugin as a local dependency.

### Development Mode

To run the test app in development mode (with hot reload):

```bash
cd test-app
pnpm dev
```

This will:

- Build the plugin's Rust code automatically
- Start the Tauri development server
- Open the application window
- Watch for changes and rebuild as needed

### Production Build

To create a production build of the test app:

```bash
cd test-app
pnpm build
```

The built application will be in `test-app/src-tauri/target/release/`.

## Quick Start (All-in-One)

To build everything and run the test app:

```bash
# 1. Install dependencies
pnpm install

# 2. Build plugin JavaScript
cd tauri-plugin-secure-element/guest-js && pnpm build && cd .. && pnpm build

# 3. Run test app (Rust builds automatically)
cd ../../test-app && pnpm dev
```
