#include "noleax/version.hpp"

#include <catch2/catch_test_macros.hpp>

TEST_CASE("version constants match the version string", "[version]") {
  CHECK(noleax::kVersionMajor == 0);
  CHECK(noleax::kVersionMinor == 5);
  CHECK(noleax::kVersionPatch == 0);
  CHECK(noleax::version_string() == "0.5.0-dev");
}
