import Testing
@testable import NostrPasskey

@Suite("NostrPasskey Tests")
struct NostrPasskeyTests {

    @Test("Generate random keypair")
    func generateKeypair() throws {
        let keypair = try NostrPasskeyKeypair.generate()
        #expect(keypair.publicKeyHex.count == 64)
        #expect(keypair.npub.hasPrefix("npub1"))
        #expect(keypair.exportNsec().hasPrefix("nsec1"))
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

    @Test("NIP-19 npub encode/decode roundtrip")
    func nip19NpubRoundtrip() throws {
        let keypair = try NostrPasskeyKeypair.generate()
        let encoded = try NIP19.npubEncode(publicKeyHex: keypair.publicKeyHex)
        #expect(encoded.hasPrefix("npub1"))
        let decoded = try NIP19.npubDecode(encoded)
        #expect(decoded == keypair.publicKeyHex)
    }

    @Test("NIP-19 nsec encode/decode roundtrip")
    func nip19NsecRoundtrip() throws {
        let keypair = try NostrPasskeyKeypair.generate()
        let nsec = keypair.exportNsec()
        let hex = try NIP19.nsecDecode(nsec)
        let reencoded = try NIP19.nsecEncode(privateKeyHex: hex)
        #expect(reencoded == nsec)
    }

    @Test("NIP-19 validation")
    func nip19Validation() throws {
        let keypair = try NostrPasskeyKeypair.generate()
        #expect(NIP19.isValidNpub(keypair.npub))
        #expect(NIP19.isValidNsec(keypair.exportNsec()))
        #expect(NIP19.isValidHexPubkey(keypair.publicKeyHex))
        #expect(!NIP19.isValidNpub("not-an-npub"))
        #expect(!NIP19.isValidNsec("not-an-nsec"))
        #expect(!NIP19.isValidHexPubkey("too-short"))
    }

    @Test("Deterministic key from hex")
    func deterministicFromHex() throws {
        let a = try NostrPasskeyKeypair.fromHex("6b911fd37cdf5c81d4c0adb1ab7fa822ed253ab0ad9aa18d77257c88b29b718e")
        let b = try NostrPasskeyKeypair.fromHex("6b911fd37cdf5c81d4c0adb1ab7fa822ed253ab0ad9aa18d77257c88b29b718e")
        #expect(a.publicKeyHex == b.publicKeyHex)
        #expect(a.npub == b.npub)
    }
}
