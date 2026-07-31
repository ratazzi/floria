// swift-tools-version:6.0
import PackageDescription

let package = Package(
    name: "floria-menubar",
    platforms: [.macOS(.v15)],
    targets: [
        .executableTarget(
            name: "floria-menubar",
            path: "Sources/floria-menubar",
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
        .testTarget(
            name: "floria-menubar-tests",
            dependencies: ["floria-menubar"],
            path: "Tests/floria-menubar-tests",
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
    ]
)
