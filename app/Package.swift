// swift-tools-version:6.0
import PackageDescription

let package = Package(
    name: "accessfs-menubar",
    platforms: [.macOS(.v15)],
    targets: [
        .executableTarget(
            name: "accessfs-menubar",
            path: "Sources/accessfs-menubar",
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
        .testTarget(
            name: "accessfs-menubar-tests",
            dependencies: ["accessfs-menubar"],
            path: "Tests/accessfs-menubar-tests",
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
    ]
)
