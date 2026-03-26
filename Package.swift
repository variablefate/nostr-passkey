// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "NostrPasskey",
    platforms: [.iOS(.v17)],
    products: [
        .library(name: "NostrPasskey", targets: ["NostrPasskey"]),
    ],
    dependencies: [
        .package(url: "https://github.com/rust-nostr/nostr-sdk-swift.git", from: "0.44.0"),
    ],
    targets: [
        .target(
            name: "NostrPasskey",
            dependencies: [
                .product(name: "NostrSDK", package: "nostr-sdk-swift"),
            ]
        ),
        .testTarget(
            name: "NostrPasskeyTests",
            dependencies: ["NostrPasskey"]
        ),
    ]
)
