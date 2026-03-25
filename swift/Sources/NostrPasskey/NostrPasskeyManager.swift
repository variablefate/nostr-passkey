import AuthenticationServices
import CryptoKit
import Foundation

/// Creates and recovers Nostr identities using passkeys with the WebAuthn PRF extension.
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
/// // Create a new identity
/// let keypair = try await manager.createPasskeyAndDeriveKey()
/// print(keypair.npub) // npub1...
///
/// // Recover on another device
/// let recovered = try await manager.authenticateAndDeriveKey()
/// // recovered.npub == keypair.npub (deterministic)
/// ```
@MainActor @Observable
public final class NostrPasskeyManager: NSObject,
    ASAuthorizationControllerDelegate,
    ASAuthorizationControllerPresentationContextProviding,
    Sendable
{
    /// The relying party identifier (your domain, e.g., "example.com").
    public let relyingPartyID: String

    /// The PRF salt used for key derivation. Must be identical across platforms
    /// for cross-platform key recovery. Default: "nostr-key-v1".
    public let prfSalt: Data

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
    ///   - prfSalt: Salt for PRF key derivation. Default "nostr-key-v1". Must match across platforms.
    ///   - credentialName: Display name in the passkey dialog. Default "Nostr Key".
    public init(
        relyingPartyID: String,
        prfSalt: String = "nostr-key-v1",
        credentialName: String = "Nostr Key"
    ) {
        self.relyingPartyID = relyingPartyID
        self.prfSalt = prfSalt.data(using: .utf8)!
        self.credentialName = credentialName
    }

    // MARK: - Public API

    /// Create a new passkey and derive a Nostr keypair from it.
    ///
    /// This registers a new passkey with the OS. The passkey syncs via iCloud Keychain.
    /// The derived Nostr key is deterministic — the same passkey always produces the same key.
    @available(iOS 18.0, *)
    public func createPasskeyAndDeriveKey() async throws -> NostrPasskeyKeypair {
        let prfKey = try await createPasskey()
        return try deriveNostrKey(from: prfKey)
    }

    /// Authenticate with an existing passkey and derive the Nostr keypair.
    ///
    /// Use this for key recovery on a new device. The passkey is available via iCloud Keychain.
    @available(iOS 18.0, *)
    public func authenticateAndDeriveKey() async throws -> NostrPasskeyKeypair {
        let prfKey = try await authenticateWithPasskey()
        return try deriveNostrKey(from: prfKey)
    }

    // MARK: - Registration

    @available(iOS 18.0, *)
    private func createPasskey() async throws -> SymmetricKey {
        isProcessing = true
        error = nil
        defer { isProcessing = false }

        let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(
            relyingPartyIdentifier: relyingPartyID
        )

        var challengeBytes = [UInt8](repeating: 0, count: 32)
        _ = SecRandomCopyBytes(kSecRandomDefault, 32, &challengeBytes)
        var userIdBytes = [UInt8](repeating: 0, count: 16)
        _ = SecRandomCopyBytes(kSecRandomDefault, 16, &userIdBytes)

        let request = provider.createCredentialRegistrationRequest(
            challenge: Data(challengeBytes),
            name: credentialName,
            userID: Data(userIdBytes)
        )

        let inputValues = ASAuthorizationPublicKeyCredentialPRFRegistrationInput.InputValues(
            saltInput1: prfSalt
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

    // MARK: - Assertion

    @available(iOS 18.0, *)
    private func authenticateWithPasskey() async throws -> SymmetricKey {
        isProcessing = true
        error = nil
        defer { isProcessing = false }

        let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(
            relyingPartyIdentifier: relyingPartyID
        )

        var challengeBytes = [UInt8](repeating: 0, count: 32)
        _ = SecRandomCopyBytes(kSecRandomDefault, 32, &challengeBytes)

        let request = provider.createCredentialAssertionRequest(
            challenge: Data(challengeBytes)
        )

        let inputValues = ASAuthorizationPublicKeyCredentialPRFAssertionInput.InputValues(
            saltInput1: prfSalt
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

    // MARK: - Key Derivation

    /// Derive a Nostr keypair from PRF output.
    ///
    /// Algorithm: SHA-256(PRF output bytes) → 32-byte secp256k1 private key
    /// This is deterministic: same PRF output always produces the same Nostr key.
    private func deriveNostrKey(from symmetricKey: SymmetricKey) throws -> NostrPasskeyKeypair {
        let rawBytes = symmetricKey.withUnsafeBytes { Data($0) }
        let digest = SHA256.hash(data: rawBytes)
        let privateKeyHex = digest.compactMap { String(format: "%02x", $0) }.joined()
        return try NostrPasskeyKeypair.fromHex(privateKeyHex)
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

/// Errors from passkey operations.
public enum NostrPasskeyError: Error, LocalizedError {
    case prfNotAvailable
    case prfNotSupported
    case prfOutputMissing
    case unexpectedCredentialType
    case authenticationFailed(String)

    public var errorDescription: String? {
        switch self {
        case .prfNotAvailable: "Passkey login requires iOS 18 or later."
        case .prfNotSupported: "Your device doesn't support passkey-based key derivation."
        case .prfOutputMissing: "Passkey authentication succeeded but key derivation failed. Please try again."
        case .unexpectedCredentialType: "Unexpected credential type. Please try again."
        case .authenticationFailed(let detail):
            detail.contains("cancelled") ? nil : "Authentication failed: \(detail)"
        }
    }
}
