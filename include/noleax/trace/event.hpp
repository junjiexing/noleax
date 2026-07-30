#pragma once

#include <cstdint>
#include <stdexcept>
#include <variant>

#include "noleax/trace/identifiers.hpp"

namespace noleax::trace {

using Address = std::uint64_t;
using RawHandle = std::uint64_t;

enum class EventOperation : std::uint8_t {
  kHeapCreate,
  kHeapDestroy,
  kAllocate,
  kReallocate,
  kFree,
  kVmAllocate,
  kVmFree,
  kMap,
  kUnmap,
};

enum class EventStatus : std::uint8_t {
  kSuccess,
  kFailure,
  kUnmatched,
  kPreexisting,
};

enum class SystemErrorDomain : std::uint8_t {
  kNone,
  kWin32,
  kNtStatus,
  kPosix,
  kMach,
};

enum class ProcessMemoryScope : std::uint8_t {
  kCurrentProcess,
  kRemoteProcess,
  kUnknown,
};

enum class ReallocationEffect : std::uint8_t {
  kNoChange,
  kNewGeneration,
  kFreed,
};

struct SystemError {
  SystemErrorDomain domain{SystemErrorDomain::kNone};
  std::uint64_t code{0};

  bool operator==(const SystemError&) const = default;
};

struct EventHeader {
  Sequence sequence;
  std::uint64_t monotonic_ticks{0};
  std::uint64_t thread_id{0};
  ApiId api_id{0};
  EventStatus status{EventStatus::kFailure};
  StackId stack_id;
  std::uint32_t flags{0};
  SystemError system_error;

  bool operator==(const EventHeader&) const = default;
};

struct ProcessTarget {
  ProcessMemoryScope scope{ProcessMemoryScope::kUnknown};
  RawHandle process_handle{0};
  std::uint64_t process_id{0};

  bool operator==(const ProcessTarget&) const = default;
};

struct HeapCreateEvent {
  RawHandle heap_handle{0};
  HeapId heap_id;
  std::uint64_t heap_flags{0};
  std::uint64_t reserve_size{0};
  std::uint64_t commit_size{0};

  bool operator==(const HeapCreateEvent&) const = default;
};

struct HeapDestroyEvent {
  RawHandle heap_handle{0};
  HeapId heap_id;
  std::uint64_t raw_result{0};

  bool operator==(const HeapDestroyEvent&) const = default;
};

struct AllocationEvent {
  RawHandle heap_handle{0};
  HeapId heap_id;
  std::uint64_t requested_size{0};
  Address result_address{0};
  AllocationId allocation_id;
  std::uint64_t api_flags{0};

  bool operator==(const AllocationEvent&) const = default;
};

struct ReallocationEvent {
  RawHandle heap_handle{0};
  HeapId heap_id;
  Address old_address{0};
  AllocationId old_allocation_id;
  std::uint64_t requested_size{0};
  Address result_address{0};
  AllocationId new_allocation_id;
  std::uint64_t api_flags{0};
  ReallocationEffect effect{ReallocationEffect::kNoChange};

  bool operator==(const ReallocationEvent&) const = default;
};

struct FreeEvent {
  RawHandle heap_handle{0};
  HeapId heap_id;
  Address address{0};
  AllocationId allocation_id;
  std::uint64_t raw_result{0};
  std::uint64_t api_flags{0};

  bool operator==(const FreeEvent&) const = default;
};

struct VmAllocateEvent {
  ProcessTarget target;
  Address requested_base{0};
  Address result_base{0};
  std::uint64_t requested_size{0};
  std::uint64_t result_size{0};
  Address mapping_base{0};
  std::uint64_t mapping_size{0};
  std::uint32_t allocation_type{0};
  std::uint32_t protection{0};
  MappingId mapping_id;

  bool operator==(const VmAllocateEvent&) const = default;
};

struct VmFreeEvent {
  ProcessTarget target;
  Address base{0};
  std::uint64_t region_size{0};
  std::uint32_t free_type{0};
  MappingId mapping_id;

  bool operator==(const VmFreeEvent&) const = default;
};

struct MapEvent {
  RawHandle section_handle{0};
  ProcessTarget target;
  Address result_base{0};
  std::uint64_t view_size{0};
  std::uint64_t section_offset{0};
  std::uint32_t protection{0};
  MappingId mapping_id;

  bool operator==(const MapEvent&) const = default;
};

struct UnmapEvent {
  ProcessTarget target;
  Address base{0};
  MappingId mapping_id;

  bool operator==(const UnmapEvent&) const = default;
};

using EventPayload =
    std::variant<HeapCreateEvent, HeapDestroyEvent, AllocationEvent, ReallocationEvent, FreeEvent,
                 VmAllocateEvent, VmFreeEvent, MapEvent, UnmapEvent>;

struct Event {
  EventHeader header;
  EventPayload payload;

  bool operator==(const Event&) const = default;
};

class EventValidationError final : public std::invalid_argument {
 public:
  using std::invalid_argument::invalid_argument;
};

[[nodiscard]] EventOperation event_operation(const EventPayload& payload) noexcept;
[[nodiscard]] bool call_succeeded(EventStatus status) noexcept;
[[nodiscard]] bool allocation_creates_generation(const EventHeader& header,
                                                 const AllocationEvent& event) noexcept;
[[nodiscard]] bool reallocation_ends_old_generation(const EventHeader& header,
                                                    const ReallocationEvent& event) noexcept;
[[nodiscard]] bool reallocation_creates_new_generation(const EventHeader& header,
                                                       const ReallocationEvent& event) noexcept;
[[nodiscard]] bool free_ends_generation(const EventHeader& header, const FreeEvent& event) noexcept;
[[nodiscard]] bool heap_destroy_ends_generations(const EventHeader& header,
                                                 const HeapDestroyEvent& event) noexcept;
void validate_event(const Event& event);

}  // namespace noleax::trace
