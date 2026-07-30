#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <type_traits>

namespace noleax::agent::windows {

inline constexpr std::size_t kMaximumRawModulePathCharacters = 1024U;
inline constexpr std::size_t kMaximumRawPdbPathBytes = 512U;

enum class RawModuleEventType : std::uint8_t {
  kLoad,
  kUnload,
};

enum class RawModuleEventFlag : std::uint32_t {  // NOLINT(performance-enum-size)
  kInitialSnapshot = 1U << 0U,
  kPathTruncated = 1U << 1U,
  kPdbPathTruncated = 1U << 2U,
  kHasImageIdentity = 1U << 3U,
  kHasPdbIdentity = 1U << 4U,
};

struct RawModuleEvent {
  std::uint64_t monotonic_ticks{0U};
  std::uint64_t base_address{0U};
  std::uint64_t image_size{0U};
  std::uint32_t pe_timestamp{0U};
  std::uint32_t pe_checksum{0U};
  std::uint32_t pdb_age{0U};
  std::uint32_t flags{0U};
  std::uint16_t path_length{0U};
  std::uint16_t pdb_path_length{0U};
  RawModuleEventType type{RawModuleEventType::kLoad};
  std::uint8_t reserved[3]{};
  std::array<std::byte, 16> pdb_guid{};
  std::array<wchar_t, kMaximumRawModulePathCharacters> path{};
  std::array<char, kMaximumRawPdbPathBytes> pdb_path{};

  bool operator==(const RawModuleEvent&) const = default;
};

static_assert(std::is_trivially_copyable_v<RawModuleEvent>);
static_assert(std::is_trivially_destructible_v<RawModuleEvent>);

class WindowsModuleTracker final {
 public:
  static constexpr std::size_t kDefaultQueueCapacity = 256U;

  explicit WindowsModuleTracker(std::uint64_t monotonic_origin,
                                std::size_t queue_capacity = kDefaultQueueCapacity);
  ~WindowsModuleTracker();

  WindowsModuleTracker(const WindowsModuleTracker&) = delete;
  WindowsModuleTracker& operator=(const WindowsModuleTracker&) = delete;
  WindowsModuleTracker(WindowsModuleTracker&&) = delete;
  WindowsModuleTracker& operator=(WindowsModuleTracker&&) = delete;

  [[nodiscard]] std::span<const RawModuleEvent> initial_modules() const noexcept;
  [[nodiscard]] bool try_dequeue(RawModuleEvent& event) noexcept;
  [[nodiscard]] std::uint64_t take_dropped_event_count() noexcept;
  [[nodiscard]] std::size_t queue_capacity() const noexcept;
  [[nodiscard]] bool is_registered() const noexcept;

 private:
  class Implementation;
  std::unique_ptr<Implementation> implementation_;
};

}  // namespace noleax::agent::windows
