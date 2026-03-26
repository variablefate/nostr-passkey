# FlareSign — Implementation Plan

## Environment

- Xcode 26.3, Swift 6.2, iOS 17+ (iOS 18+ for passkey)
- SwiftUI + SwiftData for persistence
- Dependencies: NostrPasskey SDK (v0.3+), nostr-sdk-swift (v0.44+)
- Repo: `~/Documents/Projects/flaresign/`
- Bundle ID: `com.flaresign.app`
- Associated Domains: `flaresign.app` (future — passkeys use roadflare.app initially)

## Project Structure

```
flaresign/
  FlareSign/
    FlareSignApp.swift
    Info.plist
    Assets.xcassets/
    Models/
      Identity.swift            // SwiftData model
      ConnectedApp.swift        // SwiftData model
      Permission.swift          // SwiftData model
      ActivityLogEntry.swift    // SwiftData model
      NIP46Message.swift        // JSON-RPC request/response types
    Services/
      IdentityManager.swift     // CRUD for identities + Keychain private keys
      NIP46Service.swift        // Core NIP-46 relay listener + response sender
      NIP46Session.swift        // Per-app session (encrypt/decrypt channel)
      NIP46URIParser.swift      // Parse nostrconnect:// and bunker:// URIs
      PermissionEngine.swift    // Policy evaluation (allow/deny/ask)
      RequestQueue.swift        // Sequential, deduped request processing
      KeychainStore.swift       // Private key storage (Keychain wrapper)
    Views/
      Shared/
        DesignSystem.swift      // Copied from RoadFlare (colors, fonts, components)
      Onboarding/
        WelcomeView.swift
        IdentityCreatedView.swift
      Tabs/
        IdentitiesTab.swift
        AppsTab.swift
        ActivityTab.swift
        SettingsTab.swift
      Sheets/
        ApproveRequestSheet.swift
        ConnectAppSheet.swift
        ShareConnectionSheet.swift
        AddIdentitySheet.swift
        ViewNsecSheet.swift
    ViewModels/
      AppState.swift            // Root observable state
  FlareSignTests/
    NIP46URIParserTests.swift
    PermissionEngineTests.swift
    NIP46MessageTests.swift
    RequestQueueTests.swift
    IdentityManagerTests.swift
```

## Implementation Steps

### Step 0: Project Scaffolding

1. Create Xcode project (iOS App, SwiftUI, SwiftData)
2. Add SPM dependencies: `nostr-passkey` (v0.3+), `nostr-sdk-swift` (v0.44+)
3. Copy `DesignSystem.swift` from RoadFlare (colors, fonts, button styles, card modifiers)
4. Create directory structure matching the plan
5. Add camera usage description to Info.plist (QR scanning)
6. `git init`, `.gitignore`, initial commit
7. Verify clean build

### Step 1: Data Models (SwiftData)

**Identity.swift**
```swift
@Model
final class Identity {
    @Attribute(.unique) var publicKeyHex: String
    var npub: String
    var label: String
    var index: Int                  // -1 for imported keys
    var isPasskeyDerived: Bool
    var createdAt: Date

    // Private key stored in Keychain, NOT in SwiftData
}
```

**ConnectedApp.swift**
```swift
@Model
final class ConnectedApp {
    var id: UUID
    var name: String
    var iconURL: String?
    var clientPubkey: String        // ephemeral NIP-46 client pubkey
    var identityPubkey: String      // which identity this app uses
    var relays: [String]
    var secret: String?             // nostrconnect:// secret for verification
    var connectedAt: Date
    var lastUsedAt: Date

    @Relationship(deleteRule: .cascade)
    var permissions: [Permission]
}
```

**Permission.swift**
```swift
@Model
final class Permission {
    var method: String              // "sign_event", "nip44_encrypt", etc.
    var kind: Int?                  // event kind (nil = all kinds)
    var policy: String              // "allow", "deny", "ask"
    var expiresAt: Date?

    var connectedApp: ConnectedApp?
}
```

**ActivityLogEntry.swift**
```swift
@Model
final class ActivityLogEntry {
    var id: UUID
    var appName: String
    var appId: UUID
    var method: String
    var kind: Int?
    var approved: Bool
    var timestamp: Date
    var eventPreview: String?       // first 100 chars of content
}
```

**NIP46Message.swift** (not SwiftData — plain Codable)
```swift
struct NIP46Request: Codable {
    let id: String
    let method: String
    let params: [String]
}

struct NIP46Response: Codable {
    let id: String
    let result: String?
    let error: String?
}
```

**Tests:** Verify models can be created, saved, queried. Verify NIP46Message encodes/decodes correctly.

### Step 2: Keychain Storage + Identity Manager

**KeychainStore.swift**
- `save(privateKeyHex:, for publicKeyHex:)` — store in Keychain keyed by pubkey
- `load(for publicKeyHex:) -> String?` — retrieve private key
- `delete(for publicKeyHex:)` — remove key
- `exists(for publicKeyHex:) -> Bool`
- Accessibility: `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`
- Reuse the pattern from RidestrSDK's `KeychainStorage`

**IdentityManager.swift** (actor)
- `createWithPasskey(index:, label:)` — derive key via NostrPasskey SDK, store in Keychain + SwiftData
- `importNsec(_:, label:)` — import existing key
- `recoverAll()` — authenticate passkey, re-derive all indexed keys
- `deleteIdentity(_:)` — remove from SwiftData + Keychain
- `getKeypair(for publicKeyHex:) -> NostrPasskeyKeypair` — reconstruct from Keychain
- `listIdentities() -> [Identity]`
- Holds reference to `NostrPasskeyManager`

**Tests:** Create identity, import nsec, delete, verify Keychain round-trip (using mock Keychain for tests).

### Step 3: NIP-46 URI Parser

**NIP46URIParser.swift**
- `parseNostrConnect(_:) -> NostrConnectParams?`
  - Extract: clientPubkey, relays, secret, name, url, image, permissions
- `parseBunker(_:) -> BunkerParams?`
  - Extract: signerPubkey, relays, secret
- `generateBunkerURI(signerPubkey:, relays:, secret:) -> String`

**Structs:**
```swift
struct NostrConnectParams {
    let clientPubkey: String
    let relays: [String]
    let secret: String?
    let name: String?
    let url: String?
    let image: String?
    let permissions: [String]
}

struct BunkerParams {
    let signerPubkey: String
    let relays: [String]
    let secret: String?
}
```

**Tests:** Parse known URIs, handle malformed input, verify generated bunker:// URIs are valid.

### Step 4: NIP-46 Service (Core Relay Communication)

**NIP46Service.swift** (actor)

The central relay listener. Manages WebSocket connections, receives Kind 24133 events, decrypts them, routes to sessions.

```
Responsibilities:
- Connect to relays (using rust-nostr Client)
- Subscribe to Kind 24133 events p-tagged to any active identity
- Decrypt incoming messages (NIP-44) using the identity's private key
- Route decrypted NIP46Request to the correct NIP46Session
- Publish NIP-44 encrypted NIP46Response back to relay
- Reconnect on disconnect (exponential backoff)
- Handle scenePhase changes (reconnect on foreground)
```

**Key methods:**
- `start(identities: [String])` — connect to relays, subscribe for all identity pubkeys
- `stop()` — disconnect, clean up
- `addSession(_: NIP46Session)` — register a new app session
- `removeSession(appId:)` — disconnect an app
- `publish(response:, to clientPubkey:, via relays:, signingWith keypair:)` — encrypt + publish

**NIP46Session.swift** — per-connected-app state:
```swift
class NIP46Session {
    let app: ConnectedApp
    let signerKeypair: NostrPasskeyKeypair  // the identity this app is bound to

    func handleRequest(_ request: NIP46Request) async -> NIP46Response
}
```

**Request routing inside handleRequest:**
- `connect` → verify secret, return "ack"
- `get_public_key` → return identity's hex pubkey
- `sign_event` → parse unsigned event JSON, check permissions, sign or queue for approval
- `nip44_encrypt` → encrypt plaintext with identity's key
- `nip44_decrypt` → decrypt ciphertext with identity's key
- `ping` → return "pong"

**Tests:** Mock relay, send known NIP-46 requests, verify correct responses. Test connect handshake, sign_event flow, encryption/decryption.

### Step 5: Permission Engine

**PermissionEngine.swift**

Stateless evaluator. Given a request + app's permission set → allow / deny / ask.

```swift
enum PermissionDecision {
    case allow
    case deny
    case ask
}

struct PermissionEngine {
    static func evaluate(
        method: String,
        kind: Int?,
        app: ConnectedApp
    ) -> PermissionDecision

    static func defaultPolicy(method: String, kind: Int?) -> PermissionDecision
}
```

**Default policies (auto-approve):**
- `get_public_key` → always allow
- `ping` → always allow
- `connect` → always ask (first time)
- `sign_event` kind 0 (metadata) → allow
- `sign_event` kind 3 (contacts) → allow
- `sign_event` kind 10002 (relay list) → allow
- `sign_event` kind 22242 (auth) → allow
- `sign_event` kind 1 (note) → ask
- `sign_event` kind 4 (DM) → ask
- `nip44_encrypt` / `nip44_decrypt` → ask

**Expiration check:** If permission has `expiresAt` and it's past, treat as `.ask`.

**Tests:** Verify every default policy. Test expiration. Test per-app override.

### Step 6: Request Queue

**RequestQueue.swift** (@Observable, @MainActor)

Sequential queue that presents one request at a time for user approval.

```swift
struct PendingRequest: Identifiable {
    let id: String                  // NIP-46 request ID
    let session: NIP46Session
    let request: NIP46Request
    let parsedEvent: UnsignedEvent? // for sign_event, the parsed event
    let appName: String
    let method: String
    let kind: Int?
    let contentPreview: String?
}

@Observable
class RequestQueue {
    var currentRequest: PendingRequest?
    private var queue: [PendingRequest] = []

    func enqueue(_ request: PendingRequest)
    func approve(remember: RememberPolicy?)
    func deny(remember: RememberPolicy?)
    private func processNext()
}
```

**Deduplication:** Same request ID from multiple relays is processed only once (tracked by ID set).

**Tests:** Enqueue multiple requests, verify sequential processing. Verify deduplication.

### Step 7: App State + Onboarding

**AppState.swift** (@Observable, @MainActor)

Root state coordinator, similar to RoadFlare's AppState pattern.

```swift
@Observable
class AppState {
    var authState: AuthState = .loading
    var identities: [Identity] = []
    var connectedApps: [ConnectedApp] = []

    let identityManager: IdentityManager
    let nip46Service: NIP46Service
    let permissionEngine: PermissionEngine
    let requestQueue: RequestQueue

    enum AuthState {
        case loading
        case onboarding      // no identities
        case ready            // has identities, main UI
    }
}
```

**WelcomeView.swift**
- Same layout pattern as RoadFlare welcome screen
- "Flare" + "Sign" split branding (orange "Sign")
- Car icon replaced with key/shield icon
- "Your keys, your identity" headline
- Bullet points: NO SEED PHRASES, NO KEY SHARING, NO TRACKING
- Create with Passkey / Import nsec / Recover buttons
- Legal text footer (TOS + Privacy)

**IdentityCreatedView.swift**
- Shows npub with tap-to-copy
- Brief explanation: "Other Nostr apps can now request signatures from FlareSign"
- "Get Started" button → main tabs

### Step 8: Main Tab Views

**IdentitiesTab.swift**
- List of identity cards (horizontal: passkey icon + label + npub)
- Orange FlareIndicator on active/selected identity
- "+" button → AddIdentitySheet
- Tap card → detail with npub copy, view nsec (biometric gate), connected apps count, delete

**AppsTab.swift**
- List of connected app cards (horizontal: app icon/initial + name + last used)
- Orange FlareIndicator on active apps
- Tap → per-app permission list with toggles
- Swipe to disconnect/revoke
- "Scan QR" FAB → ConnectAppSheet

**ActivityTab.swift**
- Chronological list grouped by date
- Each row: app icon, method name, kind label, approved/denied badge (green/red StatusDot), timestamp
- Filter chips: All / Approved / Denied
- Tap → detail view with event preview

**SettingsTab.swift**
- Relay configuration (default relays, add/remove)
- About / App Info (same pattern as RoadFlare)
- Export all identities (behind biometric)
- Version info

### Step 9: Approval + Connection Sheets

**ApproveRequestSheet.swift**
- App name + icon at top
- Event kind label (human-readable, e.g., "Short Text Note" for Kind 1)
- Content preview (first 200 chars, monospaced for raw JSON)
- For non-sign methods: method name + params summary
- Approve button (rfFlare gradient)
- Deny button (rfError)
- "Remember" toggle → dropdown: This time only / 15 min / 1 hour / Always
- Activity logged regardless of choice

**ConnectAppSheet.swift**
- QR scanner (reuse QRScannerView pattern from RoadFlare)
- Manual paste field for `nostrconnect://` URI
- Parse → show app name + requested permissions
- Approve / Deny connection

**ShareConnectionSheet.swift**
- Identity picker (which identity to share)
- QR code displaying `bunker://` URI
- Copy button for URI text
- Relay selection

**AddIdentitySheet.swift**
- "Derive Next Key" (passkey auth → next index)
- "Import nsec" (paste field)
- Label input field

**ViewNsecSheet.swift**
- Biometric gate (LAContext)
- Display nsec in monospaced font
- Tap-to-copy with confirmation
- Warning text: "Never share this key"

### Step 10: NIP-46 Integration Testing

Test the full flow end-to-end:

1. **Connect with Damus/Primal** — scan nostrconnect:// QR, verify handshake
2. **Sign a Kind 1 note** — approve in signer, verify it appears in client
3. **Auto-approve Kind 0** — verify metadata update goes through without prompt
4. **Deny a request** — verify client gets error response
5. **Revoke app** — verify client can no longer sign
6. **Multiple identities** — switch identity, verify correct pubkey returned
7. **Reconnection** — background the app, foreground, verify reconnect + pending requests

### Step 11: Polish + App Store Prep

1. App icon (key/shield with flare glow, matching RoadFlare aesthetic)
2. Launch screen (dark, minimal)
3. Privacy Policy + TOS pages on website
4. App Store screenshots (dark theme, approval flow, identity list)
5. Privacy nutrition label: "Data Not Collected"
6. TestFlight beta

## Key Risks

| Risk | Mitigation |
|------|-----------|
| iOS background WebSocket death | Phase 1: app switching UX. Phase 2: push notifications |
| Damus/Primal NIP-46 compatibility | Test early in Step 10, fix protocol issues before polish |
| App Store rejection | Precedent exists (crypto wallets, authenticators). No content moderation needed. |
| rust-nostr NIP-46 support gaps | Implement raw WebSocket + JSON if rust-nostr Client doesn't expose NIP-46 directly |
| Passkey PRF not available (< iOS 18) | Fallback to nsec import. Passkey features gated with `@available(iOS 18.0, *)` |

## Test Strategy

| Suite | Coverage |
|-------|----------|
| NIP46URIParser | Parse nostrconnect://, bunker://, malformed URIs, generate bunker:// |
| NIP46Message | Encode/decode JSON-RPC, all method types, error cases |
| PermissionEngine | Default policies, per-app overrides, expiration, edge cases |
| RequestQueue | Sequential processing, deduplication, approve/deny flow |
| IdentityManager | Create, import, delete, Keychain round-trip (mock) |
| NIP46Session | Connect handshake, sign_event, encrypt/decrypt, ping |
| Integration | Full relay flow with mock relay (connect → sign → verify) |

## Verification Checklist

1. `swift build` / Xcode build succeeds with no warnings
2. All unit tests pass
3. Create identity via passkey on real device
4. Scan nostrconnect:// QR from Damus → connection established
5. Sign a Kind 1 note from Damus → appears on Nostr
6. Auto-approve Kind 0 metadata update silently
7. Deny a request → client receives error
8. Activity log shows all requests
9. Revoke app → client disconnected
10. Background → foreground → reconnects and processes pending
11. Import nsec → same identity accessible
12. Multiple identities → correct pubkey per app
