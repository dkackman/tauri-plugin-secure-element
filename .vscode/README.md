# VS Code Debugging Configuration

This directory contains VS Code launch configurations for debugging the Tauri test app.

## Prerequisites

1. **CodeLLDB Extension**: Install the [CodeLLDB extension](https://marketplace.visualstudio.com/items?itemName=vadimcn.vscode-lldb) for Rust debugging support.

2. **Rust Toolchain**: Ensure Rust is installed and `cargo` is in your PATH.

## Launch Configurations

### 1. Launch Test App (Debug)
- **Purpose**: Launches the test app binary directly with the debugger attached
- **Use Case**: Quick debugging of the Rust backend without the full Tauri dev environment
- **Note**: This may not work perfectly as Tauri apps typically need the full dev environment

### 2. Attach to Test App
- **Purpose**: Attaches the debugger to an already running test app process
- **Use Case**: 
  1. Start the app manually with `pnpm dev` in the test-app directory
  2. Select this configuration and choose the `test-app` process from the list
  3. Set breakpoints in your Rust code and debug

### 3. Launch Test App (Tauri Dev)
- **Purpose**: Starts the app using `pnpm dev` (normal development mode)
- **Use Case**: Running the app without debugging, or as part of the compound configuration

### 4. Launch Test App (Full Debug) - Compound
- **Purpose**: Attempts to launch the app and attach the debugger
- **Use Case**: One-click debugging setup
- **Note**: The attach step may require manual process selection

## Recommended Workflow

For the best debugging experience:

1. **Manual Attach Method** (Recommended):
   - Start the app: Run `pnpm dev` in the `test-app` directory from a terminal
   - In VS Code: Use "Attach to Test App" configuration
   - Select the `test-app` process when prompted
   - Set breakpoints in your Rust code
   - The debugger will stop at breakpoints

2. **Direct Launch Method**:
   - Use "Launch Test App (Debug)" configuration
   - Set breakpoints before starting
   - Note: This may have limitations with Tauri's full environment

## Tasks

The `tasks.json` file includes build tasks:
- `build-test-app`: Builds the test app Rust code
- `build-plugin`: Builds the plugin Rust code
- `build-plugin-js`: Builds the plugin TypeScript/JavaScript
- `build-plugin-bundle`: Bundles the plugin JavaScript
- `build-all`: Builds everything in sequence

## Troubleshooting

- **Can't find process**: Make sure the app is running before trying to attach
- **Breakpoints not working**: Ensure you're using a debug build (`cargo build` not `cargo build --release`)
- **Source maps**: The configuration includes source map settings for Rust standard library

