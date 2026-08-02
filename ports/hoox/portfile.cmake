vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO junjiexing/hoox
    REF v0.1.2
    SHA512 91313f5855daa33c51a49807f280dd0af489b4f3f9946add2111afe25dced139fbb5156940e2a2942c3253e50fb0513ab9c93147105ff6ce3df54566ac2f7711
    HEAD_REF master
    PATCHES
        install-rules.patch
        windows-fls-lifecycle.patch
)

vcpkg_cmake_configure(
    SOURCE_PATH "${SOURCE_PATH}"
    OPTIONS
        -DHOOX_ENABLE_TESTS=OFF
        -DHOOX_BUILD_AMALGAMATION=OFF
        -DHOOX_WINDOWS_PATCH_PC_GUARD=ON
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
