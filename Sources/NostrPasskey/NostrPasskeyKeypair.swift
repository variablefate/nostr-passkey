import Foundation
import NostrSDK

/// A Nostr identity keypair derived from a passkey or imported from an nsec/hex key.
///
/// The private key is intentionally `internal` to discourage accidental logging or display.
/// Use `exportNsec()` when you explicitly need the private key (e.g., for backup).
public struct NostrPasskeyKeypair: Sendable, Equatable, Hashable {
    /// Public key in hex format (64 characters).
    public let publicKeyHex: String

    /// Public key in NIP-19 bech32 format (npub1...).
    public let npub: String

    /// Private key in hex format. Internal to prevent accidental exposure.
    internal let privateKeyHex: String

    /// Private key in NIP-19 bech32 format. Internal to prevent accidental exposure.
    internal let nsec: String

    private init(privateKeyHex: String, publicKeyHex: String, nsec: String, npub: String) {
        self.privateKeyHex = privateKeyHex
        self.publicKeyHex = publicKeyHex
        self.nsec = nsec
        self.npub = npub
    }

    // MARK: - Factory Methods

    /// Generate a new random keypair.
    public static func generate() throws -> NostrPasskeyKeypair {
        do {
            let keys = Keys.generate()
            return try from(keys: keys)
        } catch {
            throw NostrPasskeyError.keyDerivationFailed("Failed to generate keypair: \(error.localizedDescription)")
        }
    }

    /// Import a keypair from an nsec bech32 string (e.g., "nsec1...").
    public static func fromNsec(_ nsec: String) throws -> NostrPasskeyKeypair {
        do {
            let secretKey = try SecretKey.parse(secretKey: nsec)
            let keys = Keys(secretKey: secretKey)
            return try from(keys: keys)
        } catch let error as NostrPasskeyError {
            throw error
        } catch {
            throw NostrPasskeyError.invalidKey("Invalid nsec format.")
        }
    }

    /// Import a keypair from a hex private key (64 hex characters).
    public static func fromHex(_ hex: String) throws -> NostrPasskeyKeypair {
        do {
            let secretKey = try SecretKey.parse(secretKey: hex)
            let keys = Keys(secretKey: secretKey)
            return try from(keys: keys)
        } catch let error as NostrPasskeyError {
            throw error
        } catch {
            throw NostrPasskeyError.invalidKey("Invalid hex private key.")
        }
    }

    // MARK: - Export

    /// Export the private key as nsec bech32. Use for backup display only.
    public func exportNsec() -> String { nsec }

    /// Export the public key as npub bech32.
    public func exportNpub() -> String { npub }

    // MARK: - Internal

    private static func from(keys: Keys) throws -> NostrPasskeyKeypair {
        do {
            let secretKey = keys.secretKey()
            let publicKey = keys.publicKey()
            return NostrPasskeyKeypair(
                privateKeyHex: secretKey.toHex(),
                publicKeyHex: publicKey.toHex(),
                nsec: try secretKey.toBech32(),
                npub: try publicKey.toBech32()
            )
        } catch {
            throw NostrPasskeyError.keyDerivationFailed("Failed to encode keypair: \(error.localizedDescription)")
        }
    }

    public static func == (lhs: NostrPasskeyKeypair, rhs: NostrPasskeyKeypair) -> Bool {
        lhs.publicKeyHex == rhs.publicKeyHex
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(publicKeyHex)
    }
}
