# NostrPasskey

Create and recover Nostr identities using passkeys.

One function call to derive a deterministic Nostr keypair from a WebAuthn passkey. No seed phrases, no manual key management. The passkey syncs across devices via iCloud Keychain (iOS) or Google Password Manager (Android).

## How it works

1. User creates or authenticates with a passkey
2. The WebAuthn PRF extension produces deterministic bytes from a fixed salt
3. Those bytes are SHA-256 hashed to a 32-byte secp256k1 private key
4. The private key derives a full Nostr keypair (npub, nsec)

Same passkey + same salt = same Nostr key. Every time, on every device.

## Swift (iOS 18+)

### Installation

Add to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/variablefate/nostr-passkey.git", from: "0.1.0"),
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

// Recover on another device (same passkey → same key)
let recovered = try await manager.authenticateAndDeriveKey()
assert(recovered.npub == keypair.npub)
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
Input:  WebAuthn PRF output (from passkey credential + salt)
Salt:   UTF-8 bytes of "nostr-key-v1"
Step 1: SHA-256(PRF output bytes) → 32 bytes
Step 2: Interpret as secp256k1 private key
Step 3: Derive public key, encode as npub/nsec (NIP-19)
```

## Dependencies

| Platform | Dependency | Purpose |
|----------|-----------|---------|
| Swift | [nostr-sdk-swift](https://github.com/nicegram/nicegram-nostr-sdk-swift) | secp256k1 + bech32 |
| Swift | AuthenticationServices (system) | WebAuthn passkey API |
| Swift | CryptoKit (system) | SHA-256 |

## License

MIT
