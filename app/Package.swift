// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "accessfs-menubar",
    platforms: [.macOS(.v13)],
    targets: [
        .executableTarget(
            name: "accessfs-menubar",
            path: "Sources/accessfs-menubar"
        )
    ]
)
