# Nostr Signer App — Product Requirements Document

## Overview

A native iOS Nostr signer app that holds your private keys and signs events on behalf of other apps via NIP-46 (Nostr Connect). Identity creation and recovery is powered by passkeys (NostrPasskey SDK), eliminating seed phrases and manual key management entirely.

**Core value proposition:** One passkey, unlimited Nostr identities, zero seed phrases. Your keys never leave the signer.

## Why This Exists

- **No production iOS Nostr signer on the App Store.** Amber is Android-only. Signstr exists but isn't shipping yet. nos2x is browser-only.
- **Passkey-first is novel.** Every existing signer requires you to manually enter an nsec at least once. With passkey derivation, you can create a Nostr identity without ever seeing a raw key.
- **Hidden passphrase keys are unique.** No other signer offers VeraCrypt-style hidden identities that leave zero trace on the device.

## Target User

1. **Nostr power users** who use multiple apps (Damus, Primal, Nos, Amethyst) and want one place to manage keys
2. **Privacy-conscious users** who want hidden identities protected by a passphrase
3. **New Nostr users** onboarded via RoadFlare, who want to use their identity in other apps without re-entering keys

## Dependencies

- **NostrPasskey SDK** (v0.3+) — passkey creation, key derivation, NIP-19
- **nostr-sdk-swift** (v0.44+) — event signing, NIP-44 encryption, relay communication
- iOS 17+ (iOS 18+ for passkey features)

## Architecture

```
┌─────────────────────────────────────────────┐
│                 Signer App                   │
│                                             │
│  ┌───────────┐  ┌───────────┐  ┌─────────┐ │
│  │ Passkey   │  │ Identity  │  │ NIP-46  │ │
│  │ Manager   │  │ Store     │  │ Service │ │
│  │(NostrPass-│  │(Keychain) │  │(Relay   │ │
│  │ key SDK)  │  │           │  │ Client) │ │
│  └───────────┘  └───────────┘  └─────────┘ │
│        │              │              │       │
│        └──────────────┼──────────────┘       │
│                       │                      │
│  ┌───────────────────────────────────────┐  │
│  │         Permission Manager            │  │
│  │  (per-app, per-kind, time-based)      │  │
│  └───────────────────────────────────────┘  │
│                       │                      │
│  ┌───────────────────────────────────────┐  │
│  │           Request Queue               │  │
│  │  (sequential, deduped, audit logged)  │  │
│  └───────────────────────────────────────┘  │
└─────────────────────────────────────────────┘
         ▲                          │
         │   Kind 24133 (NIP-44)    │
         │   via shared relays      ▼
┌────────────────┐        ┌────────────────┐
│  Damus / Primal │        │  RoadFlare     │
│  (NIP-46 client)│        │  (NIP-46 client)│
└────────────────┘        └────────────────┘
```

## Features

### Phase 1: Core Signer (MVP)

#### 1.1 Onboarding
- **Create with Passkey** — one tap to create a Nostr identity (index 0)
- **Import nsec** — paste an existing nsec for users migrating from other apps
- **Recover with Passkey** — authenticate to recover all indexed identities

#### 1.2 Identity Management
- View all identities (indexed keys derived from passkey)
- Add new identity (next index)
- Name/label each identity (e.g., "Personal", "Work", "Anon")
- View npub for each identity (tap to copy)
- View nsec for backup (behind biometric auth)
- Delete identity (remove from local store — passkey can re-derive)

#### 1.3 NIP-46 Remote Signing
- **Scan `nostrconnect://` QR** from a client app to connect
- **Generate `bunker://` URI** to share with a client app
- **Sign event requests** — show event kind, content preview, approve/deny
- **Encryption requests** — NIP-44 encrypt/decrypt on behalf of client
- **`get_public_key`** — return the active identity's pubkey
- **`ping`/`pong`** — keepalive

#### 1.4 Permission Management
- **Per-app permissions** — each connected app has its own permission set
- **Per-kind policies:**
  - Auto-approve (e.g., Kind 0 metadata, Kind 3 contacts, Kind 10002 relay list)
  - Always ask (e.g., Kind 1 notes, Kind 4 DMs)
  - Deny (block specific kinds)
- **Time-based approval** — "Trust for 15 min / 1 hour / session / always"
- **Revoke app** — disconnect and delete all permissions for an app

#### 1.5 Request Approval UI
- Clear display of what's being signed (kind name, content preview, recipient)
- Approve / Deny buttons
- "Remember this choice" toggle with time options
- Queue for multiple pending requests (sequential, not stacked)

#### 1.6 Activity Log
- Chronological history of all signing requests per app
- Filter by app, by kind, by approved/denied
- Timestamp + event kind + result for each entry

### Phase 2: Advanced Features

#### 2.1 Passphrase Hidden Keys
- **Add passphrase identity** — enter a passphrase to derive a hidden key
- Hidden identities are NOT stored in the identity index
- Must re-enter passphrase each time to access
- No trace of hidden identities in the UI when not active
- Separate NIP-46 connections per hidden identity

#### 2.2 Biometric Protection
- Require Face ID / Touch ID for:
  - Viewing nsec
  - Approving sign requests (configurable: always / sensitive kinds only / never)
  - Adding new connected apps
- Configurable cooldown (every time, 1 min, 5 min, 10 min)

#### 2.3 Push Notifications
- Lightweight notification relay/proxy that sends APNs when a Kind 24133 request arrives
- User gets push notification: "[App Name] wants to sign a note"
- Tapping opens the signer to the approval screen
- Needed because iOS kills WebSocket connections in background

#### 2.4 Multi-Account QR Sharing
- Generate QR code with `bunker://` URI for easy connection
- Share `bunker://` as text for remote connection
- One-tap "Connect to [App Name]" flow

### Phase 3: Platform Expansion

#### 3.1 Android App
- Kotlin implementation using NostrPasskey Kotlin SDK
- NIP-55 (Android Signer Application) support via Intents + ContentResolver
- Feature parity with iOS Phase 1 + 2

#### 3.2 RoadFlare Integration
- Update RoadFlare iOS to support NIP-46 as a client
- Users can choose: embedded key (current) or external signer
- Automatic detection of installed signer app via universal link probe

## NIP-46 Implementation Details

### Connection Flow (Client-Initiated)

```
1. Client app displays QR code: nostrconnect://<client-pubkey>?relay=wss://...&secret=abc123&name=Damus
2. User scans QR in signer app
3. Signer parses URI, shows: "Damus wants to connect" with requested permissions
4. User approves → signer sends connect response with secret via Kind 24133
5. Client receives response, connection established
6. Client sends get_public_key → signer returns active identity's hex pubkey
7. Client sends sign_event requests as needed
```

### Connection Flow (Signer-Initiated)

```
1. User taps "Add App" in signer, generates bunker:// URI
2. User shares URI with client app (QR, paste, deep link)
3. Client sends connect request via Kind 24133
4. Signer auto-approves (initiated by signer, not client)
5. Connection established
```

### Event Format

All NIP-46 messages are Kind 24133 events, NIP-44 encrypted:

```json
{
  "kind": 24133,
  "content": "<NIP-44 encrypted JSON-RPC message>",
  "tags": [["p", "<recipient-pubkey>"]],
  "pubkey": "<sender-pubkey>"
}
```

### Relay Strategy

- Default relays: `wss://relay.damus.io`, `wss://nos.lol`, `wss://relay.primal.net`
- Per-app relay override (client specifies relay in connect URI)
- Reconnect with exponential backoff on disconnect
- Subscribe to Kind 24133 events tagged to signer's pubkey

## Data Model

### Identity
```
Identity:
  index: Int              // passkey derivation index (-1 for imported)
  label: String           // user-defined name
  publicKeyHex: String    // 64-char hex
  npub: String            // NIP-19 encoded
  createdAt: Date
  isPasskeyDerived: Bool  // true if from passkey, false if imported
```

Private keys stored in iOS Keychain, keyed by `publicKeyHex`. Never stored in the database.

### Connected App
```
ConnectedApp:
  id: UUID
  name: String            // from nostrconnect:// name param
  clientPubkey: String    // ephemeral client pubkey
  identityPubkey: String  // which identity this app is connected to
  relays: [String]        // relay URLs for communication
  connectedAt: Date
  lastUsedAt: Date
```

### Permission
```
Permission:
  appId: UUID             // foreign key to ConnectedApp
  method: String          // "sign_event", "nip44_encrypt", etc.
  kind: Int?              // event kind (nil = all kinds for this method)
  policy: Policy          // .ask, .allow, .deny
  expiresAt: Date?        // nil = permanent
```

### Activity Log Entry
```
ActivityLogEntry:
  id: UUID
  appId: UUID
  method: String
  kind: Int?
  approved: Bool
  timestamp: Date
  eventPreview: String?   // truncated content for audit
```

## Design System — "The Kinetic Beacon"

Shared with RoadFlare. The signer app uses the identical color palette, typography, and component styles.

### Color Palette

| Token | Hex | Usage |
|-------|-----|-------|
| `rfPrimary` | `#FF906C` | Primary accent, CTAs, active states |
| `rfPrimaryContainer` | `#FF784D` | Button backgrounds |
| `rfPrimaryDim` | `#FF7346` | Gradient endpoints |
| `rfSurface` | `#0E0E0E` | App background |
| `rfSurfaceContainerLow` | `#131313` | Input fields |
| `rfSurfaceContainer` | `#1A1919` | Cards |
| `rfSurfaceContainerHigh` | `#201F1F` | Elevated cards, secondary buttons |
| `rfSurfaceContainerHighest` | `#262626` | Disabled states |
| `rfOnSurface` | `#FFFFFF` | Primary text |
| `rfOnSurfaceVariant` | `#ADAAAA` | Secondary text |
| `rfOnline` | `#4ADE80` | Success, approved |
| `rfOnRide` | `#FBBF24` | Warning, pending |
| `rfOffline` | `#6B7280` | Disabled, muted |
| `rfError` | `#FF4444` | Errors, deny |

### Gradients

- **rfFlare**: `rfPrimary → rfPrimaryDim` (135°) — hero CTAs, approve button
- **rfSurfaceGradient**: `rfSurfaceContainerHigh → rfSurfaceContainer` — elevated cards

### Typography

| Style | Weight | Design | Default Size |
|-------|--------|--------|-------------|
| Display | Bold | Rounded | 56pt |
| Headline | Bold | Rounded | 28pt |
| Title | Semibold | Default | 20pt |
| Body | Regular | Default | 16pt |
| Caption | Medium | Default | 13pt |
| Mono | Regular | Monospaced | 12pt |

### Components

- **RFPrimaryButtonStyle**: Flare gradient background, black text, 24pt corner radius, press scale
- **RFSecondaryButtonStyle**: `rfSurfaceContainerHigh` background, `rfPrimary` text
- **RFGhostButtonStyle**: No background, `rfOnSurfaceVariant` text
- **rfCard()**: 16pt padding, `rfSurfaceContainer` background, 16pt corner radius
- **FlareIndicator**: 4pt wide vertical orange bar on leading edge (active/selected states)
- **StatusDot**: 10pt circle — green (approved/online), yellow (pending), gray (inactive), red (denied)

### Signer-Specific Design Notes

- **Approve button**: Uses `rfFlare` gradient (same as RoadFlare primary CTA)
- **Deny button**: `rfError` background with white text
- **App cards**: Horizontal layout with orange `FlareIndicator` on left edge (matching RoadFlare driver cards)
- **Identity cards**: Similar horizontal layout — passkey icon left, label + npub right
- **Request approval sheet**: Dark modal with event preview, approve/deny buttons, remember toggle
- **QR codes**: Orange modules on dark surface (`rfPrimary` on `rfSurfaceContainer`)

### Dark Mode Only

The signer is dark-mode only, matching RoadFlare. No light mode variant.

## UI Screens

### Onboarding
1. **Welcome** — "Your keys, your identity" + Create with Passkey / Import nsec / Recover
2. **Identity Created** — shows npub, explains what the signer does

### Main Tabs
1. **Identities** — list of all identities with labels, npubs, passkey badge
2. **Apps** — list of connected apps with last-used timestamps
3. **Activity** — chronological log of signing requests
4. **Settings** — biometrics, default relay config, about

### Modal Sheets
- **Approve Request** — event preview + Approve/Deny + Remember toggle
- **Connect App** — QR scanner + manual paste for `nostrconnect://`
- **Share Connection** — QR code + copy for `bunker://`
- **Add Identity** — derive next index / enter passphrase / import nsec
- **View nsec** — biometric gate → display nsec with copy button

## iOS Background Strategy

iOS kills WebSocket connections ~30 seconds after backgrounding. Strategy:

1. **Foreground**: maintain persistent WebSocket connections to relays
2. **Background**: connections drop (expected)
3. **Re-foreground**: reconnect immediately, process any queued requests
4. **Push notifications** (Phase 2): lightweight proxy watches for Kind 24133 events and sends APNs to wake the user. This is the only way to get real-time signing in background.
5. **Practical UX**: most signing happens while the user is actively using a Nostr app. They can switch to the signer, approve, switch back. iOS app switcher makes this fast.

## Security Considerations

- **Private keys never leave the device** — stored in iOS Keychain with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`
- **NIP-44 encrypted transport** — all NIP-46 communication is end-to-end encrypted between client and signer
- **Biometric gating** — sensitive operations require Face ID / Touch ID
- **No analytics, no telemetry, no server** — the signer only talks to Nostr relays
- **Passphrase keys are invisible** — no trace in UI, database, or Keychain unless actively derived
- **Audit log** — every signing request is logged for review
- **Client secret verification** — `nostrconnect://` secret must match to prevent spoofing
- **Request deduplication** — same request from multiple relays is processed only once

## App Store Strategy

- **Category**: Utilities
- **Age Rating**: 4+ (no user-generated content, just key management)
- **Privacy Nutrition Label**: "Data Not Collected" (same as Damus, Amber precedent)
- **Precedent**: Crypto wallets (BlueWallet, Phoenix), password managers (1Password), authenticator apps — all manage cryptographic keys on the App Store
- **Review risk**: Low. The app is a security tool, not a social network. No content moderation concerns.

## Naming Considerations

Working title: **FlareSign** (ties to the RoadFlare ecosystem while being generic enough for any Nostr use)

Alternatives: KeyFlare, NostrSign, SignFlare, Flint

## Success Metrics

1. First iOS Nostr signer on the App Store
2. Successful NIP-46 connection with Damus, Primal, and RoadFlare
3. Passkey-only onboarding works end-to-end (create identity without ever seeing an nsec)
4. Hidden passphrase identity derivation verified cross-platform with Android

## Timeline

| Phase | Scope | Estimate |
|-------|-------|----------|
| Phase 1 | Core signer MVP (identities, NIP-46, permissions, approval UI) | First priority |
| Phase 2 | Passphrase keys, biometrics, push notifications | After MVP ships |
| Phase 3 | Android app, RoadFlare integration | After iOS stable |

## References

- [NIP-46 Spec](https://github.com/nostr-protocol/nips/blob/master/46.md)
- [Amber (Android)](https://github.com/greenart7c3/Amber)
- [Signstr (iOS)](https://github.com/Signstr-app/signstr-iOS)
- [NostrPasskey SDK](https://github.com/variablefate/nostr-passkey)
- [NIP-44 Encryption](https://github.com/nostr-protocol/nips/blob/master/44.md)
