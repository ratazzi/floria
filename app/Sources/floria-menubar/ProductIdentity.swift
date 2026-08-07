enum ProductIdentity {
    static let bundleIdentifier = "floria.hola.ac"
    static let cloudKitContainerIdentifier = "iCloud.\(bundleIdentifier)"
    static let daemonServiceLabel = "\(bundleIdentifier).daemon"
    static let controlQueueLabel = "\(bundleIdentifier).control"
}
