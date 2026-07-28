# Security Policy

## Reporting a Vulnerability

Please report security vulnerabilities privately rather than opening a public issue.

Email **dkackman@gmail.com** with a description of the issue, the affected platform(s),
and, if possible, steps to reproduce. You should receive a response within a few days.

Please do not disclose the issue publicly until it has been addressed.

## Scope

This plugin wraps each platform's hardware-backed key store (Secure Enclave, Android
Keystore/StrongBox, Windows TPM/Windows Hello). Reports about the plugin's own code —
incorrect access-control flags, key scoping, error handling that leaks sensitive data,
IPC boundary issues, etc. — are in scope. Reports about the underlying platform security
hardware or OS itself are out of scope; please report those to the platform vendor.

See the [Security model](tauri-plugin-secure-element/README.md#security-model) section
of the README for the plugin's documented threat model and known platform-specific
limitations — several of the differences described there (e.g. Windows key scoping,
deletion requiring no authentication) are known, intentional trade-offs rather than bugs.
