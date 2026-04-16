// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "SeckitKeychainHelper",
    platforms: [
        .macOS(.v13),
    ],
    products: [
        .executable(name: "seckit-keychain-helper", targets: ["seckit-keychain-helper"]),
    ],
    targets: [
        .target(
            name: "SeckitKeychainCore",
            path: "Sources/SeckitKeychainCore"
        ),
        .executableTarget(
            name: "seckit-keychain-helper",
            dependencies: ["SeckitKeychainCore"],
            path: "Sources/seckit-keychain-helper"
        ),
        .testTarget(
            name: "SeckitKeychainCoreTests",
            dependencies: ["SeckitKeychainCore"],
            path: "Tests/SeckitKeychainCoreTests"
        ),
    ]
)
