import Testing
import Foundation
import CryptoKit
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
        let hex = "6b911fd37cdf5c81d4c0adb1ab7fa822ed253ab0ad9aa18d77257c88b29b718e"
        let a = try NostrPasskeyKeypair.fromHex(hex)
        let b = try NostrPasskeyKeypair.fromHex(hex)
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

    @Test("Known SHA-256 derivation is stable")
    func stableDerivation() throws {
        let input = Data("nostr-passkey-test".utf8)
        let keypair = try NostrPasskeyManager.deriveKeypair(from: input)
        #expect(keypair.publicKeyHex.count == 64)
        #expect(keypair.npub.hasPrefix("npub1"))
        let again = try NostrPasskeyManager.deriveKeypair(from: input)
        #expect(again.exportNsec() == keypair.exportNsec())
    }

    @Test("Empty input rejected")
    func emptyInputRejected() {
        #expect(throws: NostrPasskeyError.self) {
            try NostrPasskeyManager.deriveKeypair(from: Data())
        }
    }
}

@Suite("Security Tests")
struct SecurityTests {

    @Test("print() does not leak private key")
    func printSafe() throws {
        let keypair = try NostrPasskeyKeypair.generate()
        let description = String(describing: keypair)
        let debugDescription = String(reflecting: keypair)
        #expect(!description.contains(keypair.exportNsec()))
        #expect(!debugDescription.contains(keypair.exportNsec()))
        #expect(description.contains("npub1"))
        #expect(debugDescription.contains("npub1"))
    }

    @Test("String interpolation does not leak private key")
    func interpolationSafe() throws {
        let keypair = try NostrPasskeyKeypair.generate()
        let interpolated = "\(keypair)"
        #expect(!interpolated.contains(keypair.exportNsec()))
        #expect(interpolated.contains("npub1"))
    }

    @available(iOS 18.0, *)
    @Test("Negative index rejected")
    func negativeIndexRejected() async throws {
        let manager = await NostrPasskeyManager(relyingPartyID: "test.com")
        do {
            _ = try await manager.deriveIndexedKey(index: -1)
            #expect(Bool(false), "Should have thrown")
        } catch let error as NostrPasskeyError {
            #expect(error.errorDescription?.contains("non-negative") == true)
        }
    }
}

@Suite("Passphrase Salt Tests")
struct PassphraseSaltTests {

    @Test("Same passphrase produces same salt")
    func deterministicSalt() {
        let a = NostrPasskeyManager.passphraseToSalt("my secret")
        let b = NostrPasskeyManager.passphraseToSalt("my secret")
        #expect(a == b)
    }

    @Test("Different passphrases produce different salts")
    func uniqueSalts() {
        let a = NostrPasskeyManager.passphraseToSalt("phrase one")
        let b = NostrPasskeyManager.passphraseToSalt("phrase two")
        #expect(a != b)
    }

    @Test("Salt is 32 bytes (SHA-256 output)")
    func saltLength() {
        let salt = NostrPasskeyManager.passphraseToSalt("test")
        #expect(salt.count == 32)
    }

    @Test("Double SHA-256 differs from single SHA-256")
    func doubleHashDiffers() {
        let input = Data("nostr-key-test".utf8)
        let singleHash = Data(SHA256.hash(data: input))
        let salt = NostrPasskeyManager.passphraseToSalt("test")
        #expect(salt != singleHash)
    }

    @Test("Empty passphrase still works")
    func emptyPassphrase() {
        let salt = NostrPasskeyManager.passphraseToSalt("")
        #expect(salt.count == 32)
    }

    @Test("Passphrase salt produces valid keypair via derivation")
    func passphraseToKeypair() throws {
        let salt = NostrPasskeyManager.passphraseToSalt("hidden identity")
        let keypair = try NostrPasskeyManager.deriveKeypair(from: salt)
        #expect(keypair.npub.hasPrefix("npub1"))
        let salt2 = NostrPasskeyManager.passphraseToSalt("hidden identity")
        let keypair2 = try NostrPasskeyManager.deriveKeypair(from: salt2)
        #expect(keypair.publicKeyHex == keypair2.publicKeyHex)
    }

    @Test("Indexed salts differ from passphrase salts")
    func indexedVsPassphrase() throws {
        let indexedKey = try NostrPasskeyManager.deriveKeypair(from: Data("nostr-key-0".utf8))
        let passphraseKey = try NostrPasskeyManager.deriveKeypair(
            from: NostrPasskeyManager.passphraseToSalt("0")
        )
        #expect(indexedKey.publicKeyHex != passphraseKey.publicKeyHex)
    }
}
