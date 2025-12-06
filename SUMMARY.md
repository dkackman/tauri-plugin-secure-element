# Desktop Secure Element Support - Executive Summary

## Current State
The Tauri Secure Element plugin currently supports:
- ✅ **iOS**: Secure Enclave via Swift Security Framework
- ✅ **Android**: StrongBox/TEE via Android KeyStore
- ❌ **Desktop**: All platforms stubbed (returns "Unsupported" errors)

## API Requirements
The plugin exposes 6 commands that must be supported on desktop:
1. `generate_secure_key` - EC P-256 key generation in secure hardware
2. `list_keys` - Enumerate stored keys
3. `sign_with_key` - ECDSA-SHA256 signing
4. `delete_key` - Remove keys
5. `check_secure_element_support` - Capability detection
6. `ping` - Test command (already works)

## Desktop Platform Evaluation

### macOS - ✅ RECOMMENDED (High Priority)
- **Hardware**: Secure Enclave on T2 chip (2018-2020 Intel) and Apple Silicon (M1+)
- **Coverage**: ~95% of Macs still in use
- **Implementation**: Reuse iOS Swift code (~95% identical)
- **Effort**: LOW - Minimal code changes needed
- **API**: Same Security Framework as iOS

**Recommendation**: Implement first. Easy win with high success rate.

### Windows - ⚠️ FEASIBLE (Medium Priority)
- **Hardware**: TPM 2.0 (required on Windows 11, common on Win10)
- **Coverage**: ~85% of Windows PCs (100% on Windows 11)
- **Implementation**: Native Rust via `windows-rs` crate
- **Effort**: MEDIUM - More complex APIs than macOS
- **API**: Windows CNG (Cryptography Next Generation)

**Recommendation**: Implement after macOS. Good coverage, but more complex.

### Linux - ⚠️ CHALLENGING (Low Priority)
- **Hardware**: TPM 2.0 (enterprise laptops), ARM TrustZone (limited)
- **Coverage**: ~30% have usable TEE
- **Implementation**: Native Rust via `tss-esapi` crate
- **Effort**: HIGH - Complex setup, varied hardware
- **API**: TPM2 Software Stack

**Recommendation**: Optional. Consider clear error messages instead.

## Key Design Decisions

### 1. Platform-Specific Implementations
```
mobile.rs (iOS/Android) ──> Swift/Kotlin native code
desktop.rs (router) ──┬──> macos.rs ──> Swift (reuse iOS)
                      ├──> windows.rs ──> Rust (windows-rs)
                      └──> linux.rs ──> Rust (tss-esapi)
```

### 2. Runtime Capability Detection
Desktop implementations MUST query OS capabilities at runtime because:
- Older Macs lack Secure Enclave (pre-2018)
- Windows TPM may be disabled in BIOS
- Linux TEE support is highly varied

### 3. Graceful Degradation
When secure hardware unavailable:
- Return `secure_element_supported: false`
- Provide clear error messages with remediation steps
- Don't fail silently or fall back to insecure software crypto

## Implementation Roadmap

### Phase 1: macOS Support (2-3 days)
1. Create `macos/Sources/Plugin.swift` (copy from iOS)
2. Update `desktop.rs` to route macOS calls to Swift
3. Add Secure Enclave detection
4. Test on T2 and Apple Silicon Macs
5. Handle graceful degradation for older Macs

**Deliverable**: macOS users get same security as iOS users

### Phase 2: Windows Support (1-2 weeks)
1. Add `windows-rs` dependency
2. Implement TPM 2.0 detection via WMI
3. Implement key generation using NCrypt APIs
4. Implement signing, listing, deletion
5. Test on Windows 11 (TPM required) and Windows 10

**Deliverable**: Windows users with TPM 2.0 get secure key storage

### Phase 3: Linux Support (Optional, 2-3 weeks)
1. Add `tss-esapi` dependency
2. Implement TPM device detection (`/dev/tpm0`)
3. Implement TPM 2.0 operations
4. Document permission requirements (udev rules)
5. Consider PKCS#11 alternative backend

**Deliverable**: Linux users with TPM can use secure storage

## Security Considerations

### macOS
- ✅ Keys isolated in Secure Enclave (hardware protection)
- ✅ Non-exportable private keys
- ✅ Attestation available
- ⚠️ Root user can access keychain (use app-specific ACLs)

### Windows
- ✅ Keys sealed to TPM (hardware protection)
- ✅ Non-exportable private keys
- ⚠️ Firmware TPM less secure than discrete TPM
- ⚠️ Admin can reset TPM (destroys all keys)

### Linux
- ⚠️ Requires `/dev/tpm0` permissions
- ⚠️ Security varies by TEE implementation
- ⚠️ Daemon dependency (tpm2-abrmd)

## Recommended Dependencies

```toml
[target.'cfg(target_os = "macos")'.dependencies]
security-framework = "2.9"

[target.'cfg(target_os = "windows")'.dependencies]
windows = { version = "0.52", features = [
    "Win32_Security_Cryptography",
    "Win32_System_Wmi",
] }

[target.'cfg(target_os = "linux")'.dependencies]
tss-esapi = "7.4"  # Optional
```

## Expected User Experience

### On Supported Hardware
```javascript
const support = await checkSecureElementSupport();
// { secureElementSupported: true, teeSupported: true }

const key = await generateSecureKey("my-key");
// { publicKey: "base64...", keyName: "my-key" }
```

### On Unsupported Hardware
```javascript
const support = await checkSecureElementSupport();
// { secureElementSupported: false, teeSupported: false }

await generateSecureKey("my-key");
// Error: "Secure Enclave not available (requires T2 chip or Apple Silicon)"
```

## Documentation Updates Needed

1. **README.md**: Add platform support matrix
2. **API Docs**: Document platform-specific requirements
3. **Migration Guide**: Help users handle unsupported platforms
4. **Examples**: Show capability detection patterns

## Testing Strategy

1. **Unit Tests**: Per-platform capability detection
2. **Integration Tests**: Full key lifecycle on each platform
3. **CI/CD**: Test on macOS (Intel + ARM), Windows 10/11, Linux
4. **Manual Testing**: Verify on varied hardware (T2, M1, TPM 2.0)

## Conclusion

Desktop support is **feasible and recommended** with this priority:

1. **macOS** (High Priority): Easy implementation, high success rate
2. **Windows** (Medium Priority): More effort, but good Windows 11 coverage
3. **Linux** (Low Priority): Optional due to complexity and low hardware coverage

The iOS/Android API can be fully replicated on desktop with platform-specific secure hardware. The key is robust capability detection and graceful degradation when hardware is unavailable.

---

**Next Steps**: Review evaluation documents and decide on implementation phases.

**Documents Created**:
- `DESKTOP_IMPLEMENTATION_EVALUATION.md` - Detailed platform analysis
- `DESKTOP_IMPLEMENTATION_DESIGN.md` - Technical implementation details
- `SUMMARY.md` - This executive summary
