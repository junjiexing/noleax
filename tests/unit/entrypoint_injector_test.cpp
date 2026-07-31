#include "noleax/controller/windows/entrypoint_injector.hpp"

#include <catch2/catch_test_macros.hpp>
#include <cstdint>

TEST_CASE("entrypoint patch offset keeps endbr64 intact", "[controller][injection][entrypoint]") {
  CHECK(noleax::controller::windows::entrypoint_patch_offset(0xFA1E0FF3U) == 4U);  // endbr64
  CHECK(noleax::controller::windows::entrypoint_patch_offset(0x89485348U) ==
        0U);  // typical prologue
  CHECK(noleax::controller::windows::entrypoint_patch_offset(0x00000000U) == 0U);
  CHECK(noleax::controller::windows::entrypoint_patch_offset(0xFA1E0FF2U) == 0U);  // near miss
  CHECK(noleax::controller::windows::entrypoint_patch_offset(0xFFFFFFFFU) == 0U);
}
