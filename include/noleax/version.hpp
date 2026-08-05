#pragma once

#include <cstdint>
#include <string_view>

namespace noleax {

inline constexpr std::uint32_t kVersionMajor = 0;
inline constexpr std::uint32_t kVersionMinor = 3;
inline constexpr std::uint32_t kVersionPatch = 0;
inline constexpr std::uint32_t kAgentAbiVersion = 4;

[[nodiscard]] std::string_view version_string() noexcept;

}  // namespace noleax
