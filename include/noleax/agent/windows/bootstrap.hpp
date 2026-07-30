#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <type_traits>

namespace noleax::agent::windows {

inline constexpr std::uint32_t kBootstrapVersion = 1U;
inline constexpr std::size_t kBootstrapPipeNameCapacity = 128U;

struct BootstrapParameters {
  std::uint32_t structure_size{sizeof(BootstrapParameters)};
  std::uint32_t version{kBootstrapVersion};
  std::array<wchar_t, kBootstrapPipeNameCapacity> pipe_name{};
  std::array<std::byte, 16U> session_token{};
  std::uint32_t connect_timeout_ms{10'000U};
  std::uint32_t reserved{0U};
};

static_assert(std::is_standard_layout_v<BootstrapParameters>);
static_assert(std::is_trivially_copyable_v<BootstrapParameters>);

enum class BootstrapResult : std::uint32_t {  // NOLINT(performance-enum-size)
  kSuccess = 0U,
  kInvalidParameters = 1U,
  kAlreadyStarted = 2U,
  kAllocationFailed = 3U,
  kThreadCreationFailed = 4U,
};

}  // namespace noleax::agent::windows
