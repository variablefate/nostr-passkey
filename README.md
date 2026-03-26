# NostrPasskey

Create and recover Nostr identities using passkeys.

One function call to derive a deterministic Nostr keypair from a WebAuthn passkey. No seed phrases, no manual key management. The passkey syncs across devices via iCloud Keychain (iOS) or Google Password Manager (Android).

## How it works

1. User creates or authenticates with a passkey
2. The WebAuthn PRF extension produces deterministic bytes from a salt
3. Those bytes are SHA-256 hashed to a 32-byte secp256k1 private key
4. The private key derives a full Nostr keypair (npub, nsec)

Same passkey + same salt = same Nostr key. Every time, on every device.

## Derivation Modes

| Mode | Salt | Recovery | Use case |
|------|------|----------|----------|
| **Default** | `"nostr-key-v1"` | Automatic | Single-identity apps |
| **Indexed** | `"nostr-key-{N}"` | Back up the index count | Multiple identities |
| **Passphrase** | `SHA256(SHA256("nostr-key-" + phrase))` | Must know the passphrase | Hidden/2FA identities |

Passphrase-derived keys leave no trace — they are not stored in any backup, and there is no way to detect they exist. If a device is compromised, only indexed keys are exposed.

## Swift (iOS 18+)

### Installation

Add to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/variablefate/nostr-passkey.git", from: "0.3.0"),
]
```

Then add `"NostrPasskey"` to your target's dependencies.

### Usage

```swift
import NostrPasskey

// Configure with your domain (must match Associated Domains entitlement)
let manager = NostrPasskeyManager(relyingPartyID: "yourdomain.com")

// Create a new Nostr identity with a passkey
let keypair = try await manager.createPasskeyAndDeriveKey()
print(keypair.npub) // npub1...

// Recover on another device (same passkey -> same key)
let recovered = try await manager.authenticateAndDeriveKey()
assert(recovered.npub == keypair.npub)
```

### Multiple Identities (Indexed)

```swift
// Each index derives a different key from the same passkey
let primary = try await manager.deriveIndexedKey(index: 0)
let alt     = try await manager.deriveIndexedKey(index: 1)
let work    = try await manager.deriveIndexedKey(index: 2)
```

### Hidden Passphrase Keys (2FA)

```swift
// Passphrase key: not stored anywhere, must know the passphrase to derive
let hidden = try await manager.derivePassphraseKey(passphrase: "my secret phrase")

// Same passphrase always produces the same key
let again = try await manager.derivePassphraseKey(passphrase: "my secret phrase")
assert(hidden.npub == again.npub)
```

### NIP-19 Utilities

```swift
// Encode/decode bech32
let npub = try NIP19.npubEncode(publicKeyHex: "ab12cd...")
let hex = try NIP19.npubDecode("npub1...")

// Validate
NIP19.isValidNpub("npub1...")  // true
NIP19.isValidNsec("nsec1...")  // true
```

### Requirements

- iOS 17+ (iOS 18+ for passkey features)
- Associated Domains entitlement with `webcredentials:yourdomain.com`
- `.well-known/apple-app-site-association` on your domain

### Associated Domains Setup

1. Add `webcredentials:yourdomain.com` to your app's Associated Domains entitlement
2. Host this at `https://yourdomain.com/.well-known/apple-app-site-association`:

```json
{
    "webcredentials": {
        "apps": ["TEAMID.com.yourcompany.yourapp"]
    }
}
```

## Kotlin (Android)

Coming soon. See [kotlin/README.md](kotlin/README.md) for the planned implementation.

## Cross-Platform Key Derivation Spec

The derivation algorithm is platform-agnostic. Any implementation that follows this spec produces identical keys:

```
Default:     PRF(passkey, "nostr-key-v1") -> SHA256 -> secp256k1 key
Indexed:     PRF(passkey, "nostr-key-{N}") -> SHA256 -> secp256k1 key
Passphrase:  PRF(passkey, SHA256(SHA256("nostr-key-" + phrase))) -> SHA256 -> secp256k1 key
```

## Security

- Private keys are `internal` — cannot be accessed outside the module by default
- `print(keypair)` only shows the npub, never private key material
- Passphrase salts use double SHA-256 to resist brute-force
- Concurrent passkey calls are rejected to prevent state corruption
- Random challenge bytes are validated (SecRandomCopyBytes return checked)
- Empty derivation input is rejected

## Dependencies

| Platform | Dependency | Purpose |
|----------|-----------|---------|
| Swift | [nostr-sdk-swift](https://github.com/rust-nostr/nostr-sdk-swift) | secp256k1 + bech32 |
| Swift | AuthenticationServices (system) | WebAuthn passkey API |
| Swift | CryptoKit (system) | SHA-256 |

## License

MIT
