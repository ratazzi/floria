// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "accessfs-menubar",
    platforms: [.macOS(.v14)],
    targets: [
        .executableTarget(
            name: "accessfs-menubar",
            path: "Sources/accessfs-menubar"
        ),
        .testTarget(
            name: "accessfs-menubar-tests",
            dependencies: ["accessfs-menubar"],
            path: "Tests/accessfs-menubar-tests"
        ),
    ]
)
