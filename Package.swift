// swift-tools-version:6.0
import PackageDescription

extension [Platform] {
    static let darwin: [Platform] = [.macOS, .macCatalyst, .iOS, .tvOS, .watchOS, .visionOS]
    static let nonWasm: [Platform] = [.linux, .windows, .android, .openbsd]
    static let nonDarwin: [Platform] = nonWasm + [.wasi]
}

let package = Package(
    name: "AMSMB2",
    platforms: [
        .iOS(.v14),
        .macOS(.v11),
        .macCatalyst(.v14),
        .tvOS(.v14),
        .watchOS(.v7),
        .visionOS(.v1),
    ],
    products: [
        .library(
            name: "AMSMB2",
            type: .dynamic,
            targets: ["AMSMB2"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-system.git", .upToNextMajor(from: "1.6.4")),
        .package(url: "https://github.com/apple/swift-atomics.git", .upToNextMajor(from: "1.2.0")),
    ],
    targets: [
        .target(
            name: "libsmb2",
            // Target root is our Dependencies/ dir (not the submodule) so the module map
            // can live in smb2-module/: upstream master's include/module.modulemap still
            // references dcerpc headers that were relocated into libdcerpc/ and does not
            // cover libsmb2-share-enum.h, so it cannot be used as-is.
            path: "Dependencies",
            exclude: [
                "libsmb2/lib/CMakeLists.txt",
                "libsmb2/lib/libsmb2.syms",
                "libsmb2/lib/Makefile.am",
                "libsmb2/lib/Makefile.AMIGA",
                "libsmb2/lib/Makefile.AMIGA_AROS",
                "libsmb2/lib/Makefile.AMIGA_OS3",
                "libsmb2/lib/Makefile.PS3_PPU",
                "libsmb2/lib/ps2",
                "libsmb2/lib/dreamcast",
                "libsmb2/include/module.modulemap",
            ],
            sources: [
                "libsmb2/lib",
            ],
            publicHeadersPath: "smb2-module",
            cSettings: [
                // Search headers through the shim so upstream's stale
                // include/module.modulemap never lands on a module search path.
                .headerSearchPath("smb2-module"),
                .headerSearchPath("smb2-module/apple"),
                .headerSearchPath("smb2-module/smb2"),
                .headerSearchPath("libsmb2/lib"),
                .define("_U_", to: "__attribute__((unused))"),
                .define("HAVE_CONFIG_H", to: "1"),
            ],
            linkerSettings: [
            ]
        ),
        .target(
            name: "AMSMB2",
            dependencies: [
                "libsmb2",
                .product(name: "SystemPackage", package: "swift-system", condition: .when(platforms: .nonDarwin)),
            ],
            path: "AMSMB2"
        ),
        .testTarget(
            name: "AMSMB2Tests",
            dependencies: [
                "AMSMB2",
                .product(name: "Atomics", package: "swift-atomics"),
            ],
            path: "AMSMB2Tests"
        ),
    ]
)

for target in package.targets {
    let swiftSettings: [SwiftSetting] = [
        .enableUpcomingFeature("ExistentialAny"),
    ]
    target.swiftSettings = swiftSettings
}
