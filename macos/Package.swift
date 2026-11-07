// swift-tools-version: 6.0
// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import PackageDescription

let package = Package(
    name: "NetraKit",
    platforms: [.macOS(.v15)],
    products: [.library(name: "NetraKit", targets: ["NetraKit"]),
               .executable(name: "Netra", targets: ["Netra"])],
    targets: [
        .target(name: "NetraKit"),
        .executableTarget(name: "Netra", dependencies: ["NetraKit"]),
        .testTarget(name: "NetraKitTests", dependencies: ["NetraKit"]),
    ]
)
