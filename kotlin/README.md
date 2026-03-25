# NostrPasskey — Kotlin/Android

Android implementation of passkey-to-Nostr key derivation.

## Status

Coming soon. The Kotlin implementation will use:
- Android Credential Manager API for passkey operations
- WebAuthn PRF extension for deterministic key derivation
- Same PRF salt (`nostr-key-v1`) and SHA-256 derivation as the Swift implementation

## Cross-Platform Compatibility

The key derivation algorithm is platform-agnostic:

```
PRF output (from passkey + salt "nostr-key-v1")
    → SHA-256 hash
    → 32-byte secp256k1 private key
    → Nostr keypair (npub/nsec)
```

Any implementation that follows this spec will produce identical keys from the same passkey credential.
