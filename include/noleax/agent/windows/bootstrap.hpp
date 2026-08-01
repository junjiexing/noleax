#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <type_traits>

namespace noleax::agent::windows {

inline constexpr std::uint32_t kBootstrapVersion = 2U;
inline constexpr std::size_t kBootstrapPipeNameCapacity = 128U;

struct BootstrapParameters {
  std::uint32_t structure_size{sizeof(BootstrapParameters)};
  std::uint32_t version{kBootstrapVersion};
  std::array<wchar_t, kBootstrapPipeNameCapacity> pipe_name{};
  std::array<std::byte, 16U> session_token{};
  std::uint32_t connect_timeout_ms{10'000U};
  std::uint32_t controller_process_id{0U};
};

// Session token that marks standalone capture: `noleax patch --standalone` bakes it into
// the patched image's parameter area, and the agent then records without a controller.
inline constexpr std::array<std::byte, 16U> kStandaloneMagic{
    std::byte{'N'}, std::byte{'L'}, std::byte{'X'}, std::byte{'-'}, std::byte{'S'}, std::byte{'T'},
    std::byte{'A'}, std::byte{'N'}, std::byte{'D'}, std::byte{'A'}, std::byte{'L'}, std::byte{'O'},
    std::byte{'N'}, std::byte{'E'}, std::byte{'-'}, std::byte{'1'}};

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
