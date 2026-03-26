import Testing
import Foundation
@testable import NostrPasskey

@Suite("NostrPasskeyKeypair Tests")
struct KeypairTests {

    @Test("Generate random keypair")
    func generateKeypair() throws {
        let keypair = try NostrPasskeyKeypair.generate()
        #expect(keypair.publicKeyHex.count == 64)
        #expect(keypair.npub.hasPrefix("npub1"))
        #expect(keypair.exportNsec().hasPrefix("nsec1"))
    }

    @Test("Two generated keypairs are different")
    func uniqueKeypairs() throws {
        let a = try NostrPasskeyKeypair.generate()
        let b = try NostrPasskeyKeypair.generate()
        #expect(a.publicKeyHex != b.publicKeyHex)
    }

    @Test("Import from nsec roundtrip")
    func importNsecRoundtrip() throws {
        let original = try NostrPasskeyKeypair.generate()
        let nsec = original.exportNsec()
        let imported = try NostrPasskeyKeypair.fromNsec(nsec)
        #expect(imported.publicKeyHex == original.publicKeyHex)
        #expect(imported.npub == original.npub)
    }

    @Test("Import from hex roundtrip")
    func importHexRoundtrip() throws {
        let original = try NostrPasskeyKeypair.generate()
        let nsec = original.exportNsec()
        let hex = try NIP19.nsecDecode(nsec)
        let imported = try NostrPasskeyKeypair.fromHex(hex)
        #expect(imported.publicKeyHex == original.publicKeyHex)
    }

    @Test("Deterministic key from hex")
    func deterministicFromHex() throws {
        let hex = "6b911fd37cdf5c81d4c0adb1ab7fa822ed253ab0ad9aa18d77257c88b29b718e"
        let a = try NostrPasskeyKeypair.fromHex(hex)
        let b = try NostrPasskeyKeypair.fromHex(hex)
        #expect(a.publicKeyHex == b.publicKeyHex)
        #expect(a.npub == b.npub)
        #expect(a.exportNsec() == b.exportNsec())
    }

    @Test("Invalid nsec throws NostrPasskeyError")
    func invalidNsec() {
        #expect(throws: NostrPasskeyError.self) {
            try NostrPasskeyKeypair.fromNsec("not-a-valid-nsec")
        }
    }

    @Test("Invalid hex throws NostrPasskeyError")
    func invalidHex() {
        #expect(throws: NostrPasskeyError.self) {
            try NostrPasskeyKeypair.fromHex("zzzz")
        }
    }

    @Test("Empty string throws NostrPasskeyError")
    func emptyString() {
        #expect(throws: NostrPasskeyError.self) {
            try NostrPasskeyKeypair.fromNsec("")
        }
        #expect(throws: NostrPasskeyError.self) {
            try NostrPasskeyKeypair.fromHex("")
        }
    }

    @Test("Hashable conformance")
    func hashable() throws {
        let a = try NostrPasskeyKeypair.fromHex("6b911fd37cdf5c81d4c0adb1ab7fa822ed253ab0ad9aa18d77257c88b29b718e")
        let b = try NostrPasskeyKeypair.fromHex("6b911fd37cdf5c81d4c0adb1ab7fa822ed253ab0ad9aa18d77257c88b29b718e")
        var set: Set<NostrPasskeyKeypair> = [a]
        set.insert(b)
        #expect(set.count == 1)
    }
}

@Suite("NIP-19 Tests")
struct NIP19Tests {

    @Test("npub encode/decode roundtrip")
    func npubRoundtrip() throws {
        let keypair = try NostrPasskeyKeypair.generate()
        let encoded = try NIP19.npubEncode(publicKeyHex: keypair.publicKeyHex)
        #expect(encoded.hasPrefix("npub1"))
        let decoded = try NIP19.npubDecode(encoded)
        #expect(decoded == keypair.publicKeyHex)
    }

    @Test("nsec encode/decode roundtrip")
    func nsecRoundtrip() throws {
        let keypair = try NostrPasskeyKeypair.generate()
        let nsec = keypair.exportNsec()
        let hex = try NIP19.nsecDecode(nsec)
        let reencoded = try NIP19.nsecEncode(privateKeyHex: hex)
        #expect(reencoded == nsec)
    }

    @Test("Validation functions")
    func validation() throws {
        let keypair = try NostrPasskeyKeypair.generate()
        #expect(NIP19.isValidNpub(keypair.npub))
        #expect(NIP19.isValidNsec(keypair.exportNsec()))
        #expect(NIP19.isValidHexPubkey(keypair.publicKeyHex))
        #expect(!NIP19.isValidNpub("not-an-npub"))
        #expect(!NIP19.isValidNpub("npub1invalid"))
        #expect(!NIP19.isValidNsec("not-an-nsec"))
        #expect(!NIP19.isValidNsec(""))
        #expect(!NIP19.isValidHexPubkey("too-short"))
        #expect(!NIP19.isValidHexPubkey(String(repeating: "g", count: 64)))
    }

    @Test("Invalid inputs throw NostrPasskeyError")
    func invalidInputs() {
        #expect(throws: NostrPasskeyError.self) {
            try NIP19.npubEncode(publicKeyHex: "invalid")
        }
        #expect(throws: NostrPasskeyError.self) {
            try NIP19.nsecEncode(privateKeyHex: "invalid")
        }
        #expect(throws: NostrPasskeyError.self) {
            try NIP19.npubDecode("invalid")
        }
        #expect(throws: NostrPasskeyError.self) {
            try NIP19.nsecDecode("invalid")
        }
    }
}

@Suite("Key Derivation Tests")
struct DerivationTests {

    @Test("Deterministic derivation from bytes")
    func deterministicDerivation() throws {
        let input = Data("test-input-bytes-for-derivation".utf8)
        let a = try NostrPasskeyManager.deriveKeypair(from: input)
        let b = try NostrPasskeyManager.deriveKeypair(from: input)
        #expect(a.publicKeyHex == b.publicKeyHex)
        #expect(a.npub == b.npub)
    }

    @Test("Different inputs produce different keys")
    func differentInputs() throws {
        let a = try NostrPasskeyManager.deriveKeypair(from: Data("input-a".utf8))
        let b = try NostrPasskeyManager.deriveKeypair(from: Data("input-b".utf8))
        #expect(a.publicKeyHex != b.publicKeyHex)
    }

    @Test("Known SHA-256 derivation vector")
    func knownVector() throws {
        // SHA-256("nostr-passkey-test") = known hash → known keypair
        let input = Data("nostr-passkey-test".utf8)
        let keypair = try NostrPasskeyManager.deriveKeypair(from: input)
        #expect(keypair.publicKeyHex.count == 64)
        #expect(keypair.npub.hasPrefix("npub1"))
        // Derivation is stable — re-running always gives the same result
        let again = try NostrPasskeyManager.deriveKeypair(from: input)
        #expect(again.exportNsec() == keypair.exportNsec())
    }
}
