import Foundation
import NostrSDK

/// NIP-19: bech32-encoded Nostr entities (npub, nsec).
///
/// Provides encoding and decoding between hex keys and bech32 format.
public enum NIP19 {

    /// Encode a hex public key to npub bech32.
    public static func npubEncode(publicKeyHex: String) throws -> String {
        let pubkey = try PublicKey.parse(publicKey: publicKeyHex)
        return try pubkey.toBech32()
    }

    /// Encode a hex private key to nsec bech32.
    public static func nsecEncode(privateKeyHex: String) throws -> String {
        let seckey = try SecretKey.parse(secretKey: privateKeyHex)
        return try seckey.toBech32()
    }

    /// Decode an npub bech32 string to hex public key.
    public static func npubDecode(_ npub: String) throws -> String {
        let pubkey = try PublicKey.parse(publicKey: npub)
        return pubkey.toHex()
    }

    /// Decode an nsec bech32 string to hex private key.
    public static func nsecDecode(_ nsec: String) throws -> String {
        let seckey = try SecretKey.parse(secretKey: nsec)
        return seckey.toHex()
    }

    /// Check if a string is a valid npub.
    public static func isValidNpub(_ string: String) -> Bool {
        guard string.hasPrefix("npub1") else { return false }
        return (try? PublicKey.parse(publicKey: string)) != nil
    }

    /// Check if a string is a valid nsec.
    public static func isValidNsec(_ string: String) -> Bool {
        guard string.hasPrefix("nsec1") else { return false }
        return (try? SecretKey.parse(secretKey: string)) != nil
    }

    /// Check if a string is a valid hex public key (64 hex characters).
    public static func isValidHexPubkey(_ string: String) -> Bool {
        guard string.count == 64, string.allSatisfy(\.isHexDigit) else { return false }
        return (try? PublicKey.parse(publicKey: string)) != nil
    }
}
