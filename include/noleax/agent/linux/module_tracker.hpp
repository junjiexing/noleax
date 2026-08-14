#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <type_traits>
#include <vector>

namespace noleax::agent::linux {

inline constexpr std::size_t kMaximumRawModulePathBytes = 1024U;

enum class RawModuleEventType : std::uint8_t {
  kLoad,
  kUnload,
};

enum class RawModuleEventFlag : std::uint32_t {  // NOLINT(performance-enum-size)
  kInitialSnapshot = 1U << 0U,
  kPathTruncated = 1U << 1U,
};

// Linux counterpart of the Windows RawModuleEvent. ELF image identity (build-id) is a
// format-governance decision of the port's M5, so this record intentionally carries no
// identity fields yet; the wire format treats module identity as optional.
struct RawModuleEvent {
  std::uint64_t monotonic_ticks{0U};
  std::uint64_t base_address{0U};
  std::uint64_t image_size{0U};
  std::uint32_t flags{0U};
  std::uint16_t path_length{0U};
  RawModuleEventType type{RawModuleEventType::kLoad};
  std::uint8_t reserved[1]{};
  std::array<char, kMaximumRawModulePathBytes> path{};

  bool operator==(const RawModuleEvent&) const = default;
};

static_assert(std::is_trivially_copyable_v<RawModuleEvent>);
static_assert(std::is_trivially_destructible_v<RawModuleEvent>);

// Poll-based module tracker (docs/LINUX_PORT_PLAN.md §5.7): Linux has no in-process
// loader notification, so the writer thread calls poll() from its drain loop and the
// tracker diffs a fresh dl_iterate_phdr snapshot against the live set, emitting
// load/unload events into a bounded queue. Loads and unloads between polls coalesce
// into the next batch; the module-generation model tolerates that by design.
class LinuxModuleTracker final {
 public:
  static constexpr std::size_t kDefaultQueueCapacity = 256U;

  explicit LinuxModuleTracker(std::uint64_t monotonic_origin,
                              std::size_t queue_capacity = kDefaultQueueCapacity);
  ~LinuxModuleTracker();

  LinuxModuleTracker(const LinuxModuleTracker&) = delete;
  LinuxModuleTracker& operator=(const LinuxModuleTracker&) = delete;
  LinuxModuleTracker(LinuxModuleTracker&&) = delete;
  LinuxModuleTracker& operator=(LinuxModuleTracker&&) = delete;

  // The construction-time snapshot, stamped with the monotonic origin and the
  // kInitialSnapshot flag; consumed once by the writer at capture start.
  [[nodiscard]] std::span<const RawModuleEvent> initial_modules() const noexcept;
  // Refreshes the live set and queues load/unload events for any difference.
  void poll() noexcept;
  [[nodiscard]] bool try_dequeue(RawModuleEvent& event) noexcept;
  [[nodiscard]] std::uint64_t take_dropped_event_count() noexcept;
  [[nodiscard]] std::size_t queue_capacity() const noexcept;
  [[nodiscard]] std::size_t live_module_count() const noexcept;
  // Heap footprint estimate of the tracker's storage (live set, initial snapshot, pending
  // queue), for the H4 agent-memory accounting. Labeled estimate end to end.
  [[nodiscard]] std::uint64_t estimated_storage_bytes() const noexcept;

 private:
  class Implementation;
  std::unique_ptr<Implementation> implementation_;
};

}  // namespace noleax::agent::linux
