// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "seckit-keychain-helper",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .executable(name: "seckit-keychain-helper", targets: ["seckit-keychain-helper"])
    ],
    targets: [
        .executableTarget(name: "seckit-keychain-helper")
    ]
)

