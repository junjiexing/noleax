vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO junjiexing/hoox
    REF v0.1.1
    SHA512 fad832827539a789123b78c88d4cf5f5fc096a2c2fcaebf8bb5e5fdfa09388ee5bbb1f55925688b228b22907c1a1fdc882ed3967cea452869564540743a47359
    HEAD_REF main
    PATCHES
        install-rules.patch
        windows-fls-lifecycle.patch
)

vcpkg_cmake_configure(
    SOURCE_PATH "${SOURCE_PATH}"
    OPTIONS
        -DHOOX_ENABLE_TESTS=OFF
        -DHOOX_BUILD_AMALGAMATION=OFF
)

vcpkg_cmake_install()
vcpkg_cmake_config_fixup(PACKAGE_NAME hoox CONFIG_PATH share/hoox)

file(WRITE "${CURRENT_PACKAGES_DIR}/share/hoox/hooxConfig.cmake"
    "include(\"\${CMAKE_CURRENT_LIST_DIR}/hooxTargets.cmake\")\n")

file(REMOVE_RECURSE
    "${CURRENT_PACKAGES_DIR}/debug/include"
    "${CURRENT_PACKAGES_DIR}/debug/share"
)

vcpkg_copy_pdbs()
vcpkg_install_copyright(
    FILE_LIST
        "${SOURCE_PATH}/COPYING"
        "${SOURCE_PATH}/NOTICE"
)
