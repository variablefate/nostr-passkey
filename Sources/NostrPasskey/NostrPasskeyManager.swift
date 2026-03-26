import AuthenticationServices
import CryptoKit
import Foundation
#if canImport(UIKit)
import UIKit
#endif

/// Creates and recovers Nostr identities using passkeys with the WebAuthn PRF extension.
///
/// Supports three derivation modes from a single passkey:
///
/// | Mode | Salt | Recovery | Use case |
/// |------|------|----------|----------|
/// | **Default** | `"nostr-key-v1"` | Automatic | Single-identity apps |
/// | **Indexed** | `"nostr-key-{N}"` | Back up the index count | Multiple identities |
/// | **Passphrase** | `SHA256(SHA256("nostr-key-" + phrase))` | Must know the passphrase | Hidden/2FA identities |
///
/// ## How it works
/// 1. A passkey is created (or authenticated) with a PRF salt
/// 2. The PRF output is deterministic — same passkey + same salt = same bytes
/// 3. Those bytes are SHA-256 hashed to produce a 32-byte secp256k1 private key
/// 4. The private key derives a Nostr keypair (public key, npub, nsec)
///
/// ## Requirements
/// - iOS 18.0+ (WebAuthn PRF extension)
/// - Associated Domains entitlement configured for your relying party domain
/// - `.well-known/apple-app-site-association` on your domain with `webcredentials`
///
/// ## Usage
/// ```swift
/// let manager = NostrPasskeyManager(relyingPartyID: "example.com")
///
/// // Single identity (simplest)
/// let keypair = try await manager.createPasskeyAndDeriveKey()
///
/// // Multiple indexed identities
/// let primary = try await manager.deriveIndexedKey(index: 0)
/// let alt     = try await manager.deriveIndexedKey(index: 1)
///
/// // Hidden passphrase identity (not stored anywhere)
/// let hidden = try await manager.derivePassphraseKey(passphrase: "my secret")
/// ```
@MainActor @Observable
public final class NostrPasskeyManager: NSObject,
    ASAuthorizationControllerDelegate,
    ASAuthorizationControllerPresentationContextProviding
{
    /// The relying party identifier (your domain, e.g., "example.com").
    public let relyingPartyID: String

    /// The default PRF salt used for single-key derivation.
    /// Default: "nostr-key-v1". Must be identical across platforms for cross-platform recovery.
    public let defaultSalt: Data

    /// The display name shown in the passkey creation dialog.
    public let credentialName: String

    /// Whether a passkey operation is in progress.
    public private(set) var isProcessing = false

    /// The last error message, if any.
    public private(set) var error: String?

    private var registrationContinuation: CheckedContinuation<SymmetricKey, Error>?
    private var assertionContinuation: CheckedContinuation<SymmetricKey, Error>?

    /// Create a new passkey manager.
    ///
    /// - Parameters:
    ///   - relyingPartyID: Your domain (must match Associated Domains entitlement).
    ///   - defaultSalt: Salt for single-key derivation. Default "nostr-key-v1". Must match across platforms.
    ///   - credentialName: Display name in the passkey dialog. Default "Nostr Key".
    public init(
        relyingPartyID: String,
        defaultSalt: String = "nostr-key-v1",
        credentialName: String = "Nostr Key"
    ) {
        self.relyingPartyID = relyingPartyID
        self.defaultSalt = Data(defaultSalt.utf8)
        self.credentialName = credentialName
    }

    // MARK: - Public API (Single Key)

    /// Create a new passkey and derive a Nostr keypair using the default salt.
    ///
    /// This registers a new passkey with the OS. The passkey syncs via iCloud Keychain.
    @available(iOS 18.0, *)
    public func createPasskeyAndDeriveKey() async throws -> NostrPasskeyKeypair {
        let prfKey = try await createPasskey(salt: defaultSalt)
        return try Self.deriveKeypair(from: prfKey)
    }

    /// Authenticate with an existing passkey and derive the Nostr keypair using the default salt.
    @available(iOS 18.0, *)
    public func authenticateAndDeriveKey() async throws -> NostrPasskeyKeypair {
        let prfKey = try await authenticate(salt: defaultSalt)
        return try Self.deriveKeypair(from: prfKey)
    }

    // MARK: - Public API (Indexed Keys)

    /// Derive a Nostr keypair at a specific index.
    ///
    /// Each index produces a different deterministic key from the same passkey.
    /// Store the index count in your backup so you know how many keys to recover.
    ///
    /// Salt: `"nostr-key-{index}"` (e.g., `"nostr-key-0"`, `"nostr-key-1"`)
    @available(iOS 18.0, *)
    public func deriveIndexedKey(index: Int) async throws -> NostrPasskeyKeypair {
        guard index >= 0 else { throw NostrPasskeyError.invalidKey("Key index must be non-negative.") }
        let salt = Data("nostr-key-\(index)".utf8)
        let prfKey = try await authenticate(salt: salt)
        return try Self.deriveKeypair(from: prfKey)
    }

    /// Create a new passkey and derive the key at a specific index.
    ///
    /// Use this for first-time registration when you want indexed key support.
    @available(iOS 18.0, *)
    public func createPasskeyAndDeriveIndexedKey(index: Int) async throws -> NostrPasskeyKeypair {
        guard index >= 0 else { throw NostrPasskeyError.invalidKey("Key index must be non-negative.") }
        let salt = Data("nostr-key-\(index)".utf8)
        let prfKey = try await createPasskey(salt: salt)
        return try Self.deriveKeypair(from: prfKey)
    }

    // MARK: - Public API (Passphrase Keys)

    /// Derive a hidden Nostr keypair protected by a passphrase.
    ///
    /// The passphrase is double-SHA256 hashed into the PRF salt, so:
    /// - The key is deterministic (same passphrase = same key)
    /// - The key is NOT stored in any backup index
    /// - An attacker with your passkey but not your passphrase cannot derive this key
    /// - There is no way to detect that a passphrase key exists
    ///
    /// Salt: `SHA256(SHA256("nostr-key-" + passphrase))`
    @available(iOS 18.0, *)
    public func derivePassphraseKey(passphrase: String) async throws -> NostrPasskeyKeypair {
        let salt = Self.passphraseToSalt(passphrase)
        let prfKey = try await authenticate(salt: salt)
        return try Self.deriveKeypair(from: prfKey)
    }

    // MARK: - Key Derivation (Static)

    /// Derive a Nostr keypair from arbitrary bytes.
    ///
    /// This is the core derivation function. Useful for testing, migration, or
    /// integrating with custom PRF implementations.
    ///
    /// Algorithm: `SHA-256(inputBytes) → 32-byte secp256k1 private key`
    nonisolated public static func deriveKeypair(from inputBytes: Data) throws -> NostrPasskeyKeypair {
        guard !inputBytes.isEmpty else {
            throw NostrPasskeyError.keyDerivationFailed("Cannot derive key from empty input.")
        }
        let digest = SHA256.hash(data: inputBytes)
        let privateKeyHex = digest.compactMap { String(format: "%02x", $0) }.joined()
        return try NostrPasskeyKeypair.fromHex(privateKeyHex)
    }

    /// Derive a Nostr keypair from a SymmetricKey (PRF output).
    nonisolated static func deriveKeypair(from symmetricKey: SymmetricKey) throws -> NostrPasskeyKeypair {
        let rawBytes = symmetricKey.withUnsafeBytes { Data($0) }
        return try deriveKeypair(from: rawBytes)
    }

    /// Convert a passphrase to a PRF salt using double SHA-256.
    ///
    /// Algorithm: `SHA256(SHA256("nostr-key-" + passphrase))`
    nonisolated public static func passphraseToSalt(_ passphrase: String) -> Data {
        let input = Data("nostr-key-\(passphrase)".utf8)
        let firstHash = SHA256.hash(data: input)
        let secondHash = SHA256.hash(data: Data(firstHash))
        return Data(secondHash)
    }

    // MARK: - Registration (Internal)

    @available(iOS 18.0, *)
    private func createPasskey(salt: Data) async throws -> SymmetricKey {
        guard !isProcessing else { throw NostrPasskeyError.authenticationFailed("A passkey operation is already in progress.") }
        isProcessing = true
        error = nil
        defer { isProcessing = false }

        let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(
            relyingPartyIdentifier: relyingPartyID
        )

        var challengeBytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, 32, &challengeBytes) == errSecSuccess else {
            throw NostrPasskeyError.keyDerivationFailed("Failed to generate secure random challenge.")
        }
        var userIdBytes = [UInt8](repeating: 0, count: 16)
        guard SecRandomCopyBytes(kSecRandomDefault, 16, &userIdBytes) == errSecSuccess else {
            throw NostrPasskeyError.keyDerivationFailed("Failed to generate secure random user ID.")
        }

        let request = provider.createCredentialRegistrationRequest(
            challenge: Data(challengeBytes),
            name: credentialName,
            userID: Data(userIdBytes)
        )

        let inputValues = ASAuthorizationPublicKeyCredentialPRFRegistrationInput.InputValues(
            saltInput1: salt
        )
        request.prf = .inputValues(inputValues)

        let controller = ASAuthorizationController(authorizationRequests: [request])
        controller.delegate = self
        controller.presentationContextProvider = self

        return try await withCheckedThrowingContinuation { continuation in
            self.registrationContinuation = continuation
            controller.performRequests()
        }
    }

    // MARK: - Assertion (Internal)

    @available(iOS 18.0, *)
    private func authenticate(salt: Data) async throws -> SymmetricKey {
        guard !isProcessing else { throw NostrPasskeyError.authenticationFailed("A passkey operation is already in progress.") }
        isProcessing = true
        error = nil
        defer { isProcessing = false }

        let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(
            relyingPartyIdentifier: relyingPartyID
        )

        var challengeBytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, 32, &challengeBytes) == errSecSuccess else {
            throw NostrPasskeyError.keyDerivationFailed("Failed to generate secure random challenge.")
        }

        let request = provider.createCredentialAssertionRequest(
            challenge: Data(challengeBytes)
        )

        let inputValues = ASAuthorizationPublicKeyCredentialPRFAssertionInput.InputValues(
            saltInput1: salt
        )
        request.prf = .inputValues(inputValues)

        let controller = ASAuthorizationController(authorizationRequests: [request])
        controller.delegate = self
        controller.presentationContextProvider = self

        return try await withCheckedThrowingContinuation { continuation in
            self.assertionContinuation = continuation
            controller.performRequests()
        }
    }

    // MARK: - ASAuthorizationControllerDelegate

    nonisolated public func authorizationController(
        controller: ASAuthorizationController,
        didCompleteWithAuthorization authorization: ASAuthorization
    ) {
        Task { @MainActor in
            if #available(iOS 18.0, *) {
                if let registration = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialRegistration {
                    guard let prfOutput = registration.prf,
                          prfOutput.isSupported,
                          let prfBytes = prfOutput.first else {
                        registrationContinuation?.resume(throwing: NostrPasskeyError.prfNotSupported)
                        registrationContinuation = nil
                        return
                    }
                    registrationContinuation?.resume(returning: prfBytes)
                    registrationContinuation = nil
                    return
                }

                if let assertion = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialAssertion {
                    guard let prfOutput = assertion.prf else {
                        assertionContinuation?.resume(throwing: NostrPasskeyError.prfOutputMissing)
                        assertionContinuation = nil
                        return
                    }
                    assertionContinuation?.resume(returning: prfOutput.first)
                    assertionContinuation = nil
                    return
                }
            }

            registrationContinuation?.resume(throwing: NostrPasskeyError.unexpectedCredentialType)
            registrationContinuation = nil
            assertionContinuation?.resume(throwing: NostrPasskeyError.unexpectedCredentialType)
            assertionContinuation = nil
        }
    }

    nonisolated public func authorizationController(
        controller: ASAuthorizationController,
        didCompleteWithError error: Error
    ) {
        Task { @MainActor in
            let passkeyError = NostrPasskeyError.authenticationFailed(error.localizedDescription)
            self.error = error.localizedDescription
            if let cont = registrationContinuation {
                cont.resume(throwing: passkeyError)
                registrationContinuation = nil
            } else if let cont = assertionContinuation {
                cont.resume(throwing: passkeyError)
                assertionContinuation = nil
            }
        }
    }

    // MARK: - Presentation

    nonisolated public func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
        #if canImport(UIKit)
        let scenes = UIApplication.shared.connectedScenes
        let windowScene = scenes.first as? UIWindowScene
        return windowScene?.windows.first ?? ASPresentationAnchor()
        #else
        return ASPresentationAnchor()
        #endif
    }
}

/// Errors from NostrPasskey operations.
public enum NostrPasskeyError: Error, LocalizedError {
    case prfNotAvailable
    case prfNotSupported
    case prfOutputMissing
    case unexpectedCredentialType
    case invalidKey(String)
    case keyDerivationFailed(String)
    case authenticationFailed(String)

    public var errorDescription: String? {
        switch self {
        case .prfNotAvailable: "Passkey login requires iOS 18 or later."
        case .prfNotSupported: "Your device doesn't support passkey-based key derivation."
        case .prfOutputMissing: "Passkey authentication succeeded but key derivation failed. Please try again."
        case .unexpectedCredentialType: "Unexpected credential type. Please try again."
        case .invalidKey(let detail): "Invalid key: \(detail)"
        case .keyDerivationFailed(let detail): "Key derivation failed: \(detail)"
        case .authenticationFailed(let detail):
            detail.contains("cancelled") ? nil : "Authentication failed: \(detail)"
        }
    }
}
