#pragma once

#include <string_view>

namespace noleax::analyzer::detail {

[[nodiscard]] bool is_valid_utf8(std::string_view value) noexcept;

}  // namespace noleax::analyzer::detail
