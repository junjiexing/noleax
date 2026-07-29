#include "noleax/trace/event.hpp"

#include <string>
#include <type_traits>
#include <variant>

namespace noleax::trace {
namespace {

template <typename... Visitors>
struct Overloaded : Visitors... {
  using Visitors::operator()...;
};

template <typename... Visitors>
Overloaded(Visitors...) -> Overloaded<Visitors...>;

[[noreturn]] void fail(const char* message) { throw EventValidationError{message}; }

[[nodiscard]] bool is_known_status(EventStatus status) noexcept {
  switch (status) {
    case EventStatus::kSuccess:
    case EventStatus::kFailure:
    case EventStatus::kUnmatched:
    case EventStatus::kPreexisting:
      return true;
  }
  return false;
}

[[nodiscard]] bool is_known_error_domain(SystemErrorDomain domain) noexcept {
  switch (domain) {
    case SystemErrorDomain::kNone:
    case SystemErrorDomain::kWin32:
    case SystemErrorDomain::kNtStatus:
    case SystemErrorDomain::kPosix:
    case SystemErrorDomain::kMach:
      return true;
  }
  return false;
}

[[nodiscard]] bool is_known_process_scope(ProcessMemoryScope scope) noexcept {
  switch (scope) {
    case ProcessMemoryScope::kCurrentProcess:
    case ProcessMemoryScope::kRemoteProcess:
    case ProcessMemoryScope::kUnknown:
      return true;
  }
  return false;
}

[[nodiscard]] bool is_known_reallocation_effect(ReallocationEffect effect) noexcept {
  switch (effect) {
    case ReallocationEffect::kNoChange:
    case ReallocationEffect::kNewGeneration:
    case ReallocationEffect::kFreed:
      return true;
  }
  return false;
}

void validate_call_result_status(EventStatus status, const char* operation) {
  if (status != EventStatus::kSuccess && status != EventStatus::kFailure) {
    throw EventValidationError{std::string{operation} + " status must be success or failure"};
  }
}

void validate_header(const EventHeader& header) {
  if (!header.sequence) {
    fail("event sequence must not be zero");
  }
  if (!is_known_status(header.status)) {
    fail("event status is not supported");
  }
  if (!is_known_error_domain(header.system_error.domain)) {
    fail("event error domain is not supported");
  }
  if (header.system_error.domain == SystemErrorDomain::kNone && header.system_error.code != 0U) {
    fail("an event without an error domain must have a zero error code");
  }
}

void validate_heap_create(const EventHeader& header, const HeapCreateEvent& event) {
  validate_call_result_status(header.status, "heap create");
  if (call_succeeded(header.status)) {
    if (event.heap_handle == 0U || !event.heap_id) {
      fail("successful heap create must have a handle and heap_id");
    }
  } else if (event.heap_id) {
    fail("failed heap create must not have a heap_id");
  }
}

void validate_heap_destroy(const EventHeader& header, const HeapDestroyEvent& event) {
  if (header.status == EventStatus::kSuccess && !event.heap_id) {
    fail("matched successful heap destroy must have a heap_id");
  }
  if ((header.status == EventStatus::kUnmatched || header.status == EventStatus::kPreexisting) &&
      event.heap_id) {
    fail("unmatched or preexisting heap destroy must not have a heap_id");
  }
}

void validate_allocation(const EventHeader& header, const AllocationEvent& event) {
  validate_call_result_status(header.status, "allocation");
  if (call_succeeded(header.status)) {
    if (event.result_address == 0U || !event.allocation_id) {
      fail("successful allocation must have an address and allocation_id");
    }
  } else if (event.result_address != 0U || event.allocation_id) {
    fail("failed allocation must not have a result address or allocation_id");
  }
}

void validate_reallocation(const EventHeader& header, const ReallocationEvent& event) {
  if (!is_known_reallocation_effect(event.effect)) {
    fail("reallocation effect is not supported");
  }
  if ((header.status == EventStatus::kUnmatched || header.status == EventStatus::kPreexisting) &&
      event.old_allocation_id) {
    fail("unmatched or preexisting reallocation must not have an old allocation_id");
  }
  if (!call_succeeded(header.status)) {
    if (event.effect != ReallocationEffect::kNoChange || event.result_address != 0U ||
        event.new_allocation_id) {
      fail("failed reallocation must preserve the old generation and have no new generation");
    }
    return;
  }

  switch (event.effect) {
    case ReallocationEffect::kNoChange:
      if (event.result_address != 0U || event.new_allocation_id) {
        fail("no-change reallocation must not have a result or new allocation_id");
      }
      break;
    case ReallocationEffect::kNewGeneration:
      if (event.result_address == 0U || !event.new_allocation_id) {
        fail("successful reallocation must have a result and new allocation_id");
      }
      if (event.old_allocation_id && event.old_allocation_id == event.new_allocation_id) {
        fail("reallocation generations must have different allocation IDs");
      }
      break;
    case ReallocationEffect::kFreed:
      if (!event.old_allocation_id) {
        fail("freeing reallocation must identify the old generation");
      }
      if (event.result_address != 0U || event.new_allocation_id) {
        fail("freeing reallocation must not have a result or new allocation_id");
      }
      break;
  }
}

void validate_free(const EventHeader& header, const FreeEvent& event) {
  if (header.status == EventStatus::kSuccess && !event.allocation_id) {
    fail("matched successful free must have an allocation_id");
  }
  if ((header.status == EventStatus::kUnmatched || header.status == EventStatus::kPreexisting) &&
      event.allocation_id) {
    fail("unmatched or preexisting free must not have an allocation_id");
  }
}

void validate_mapping_creation(const EventHeader& header, const ProcessTarget& target,
                               MappingId mapping_id) {
  if (!is_known_process_scope(target.scope)) {
    fail("process memory scope is not supported");
  }
  validate_call_result_status(header.status, "mapping creation");
  if (!call_succeeded(header.status) && mapping_id) {
    fail("failed virtual memory operation must not have a mapping_id");
  }
  if (target.scope != ProcessMemoryScope::kCurrentProcess && mapping_id) {
    fail("non-local virtual memory events must not have a mapping_id");
  }
  if (call_succeeded(header.status) && target.scope == ProcessMemoryScope::kCurrentProcess &&
      !mapping_id) {
    fail("successful current-process mapping must have a mapping_id");
  }
}

void validate_mapping_end(const EventHeader& header, const ProcessTarget& target,
                          MappingId mapping_id) {
  if (!is_known_process_scope(target.scope)) {
    fail("process memory scope is not supported");
  }
  if (target.scope != ProcessMemoryScope::kCurrentProcess && mapping_id) {
    fail("non-local virtual memory events must not have a mapping_id");
  }
  if ((header.status == EventStatus::kUnmatched || header.status == EventStatus::kPreexisting) &&
      mapping_id) {
    fail("unmatched or preexisting virtual memory event must not have a mapping_id");
  }
  if (header.status == EventStatus::kSuccess &&
      target.scope == ProcessMemoryScope::kCurrentProcess && !mapping_id) {
    fail("matched successful local virtual memory event must have a mapping_id");
  }
}

}  // namespace

EventOperation event_operation(const EventPayload& payload) noexcept {
  return std::visit(Overloaded{
                        [](const HeapCreateEvent&) { return EventOperation::kHeapCreate; },
                        [](const HeapDestroyEvent&) { return EventOperation::kHeapDestroy; },
                        [](const AllocationEvent&) { return EventOperation::kAllocate; },
                        [](const ReallocationEvent&) { return EventOperation::kReallocate; },
                        [](const FreeEvent&) { return EventOperation::kFree; },
                        [](const VmAllocateEvent&) { return EventOperation::kVmAllocate; },
                        [](const VmFreeEvent&) { return EventOperation::kVmFree; },
                        [](const MapEvent&) { return EventOperation::kMap; },
                        [](const UnmapEvent&) { return EventOperation::kUnmap; },
                    },
                    payload);
}

bool call_succeeded(EventStatus status) noexcept { return status != EventStatus::kFailure; }

bool allocation_creates_generation(const EventHeader& header,
                                   const AllocationEvent& event) noexcept {
  return call_succeeded(header.status) && event.allocation_id.is_valid();
}

bool reallocation_ends_old_generation(const EventHeader& header,
                                      const ReallocationEvent& event) noexcept {
  return call_succeeded(header.status) && event.old_allocation_id.is_valid() &&
         (event.effect == ReallocationEffect::kNewGeneration ||
          event.effect == ReallocationEffect::kFreed);
}

bool reallocation_creates_new_generation(const EventHeader& header,
                                         const ReallocationEvent& event) noexcept {
  return call_succeeded(header.status) && event.effect == ReallocationEffect::kNewGeneration &&
         event.new_allocation_id.is_valid();
}

bool free_ends_generation(const EventHeader& header, const FreeEvent& event) noexcept {
  return call_succeeded(header.status) && event.allocation_id.is_valid();
}

bool heap_destroy_ends_generations(const EventHeader& header,
                                   const HeapDestroyEvent& event) noexcept {
  return call_succeeded(header.status) && event.heap_id.is_valid();
}

void validate_event(const Event& event) {
  validate_header(event.header);
  std::visit(
      Overloaded{
          [&event](const HeapCreateEvent& payload) { validate_heap_create(event.header, payload); },
          [&event](const HeapDestroyEvent& payload) {
            validate_heap_destroy(event.header, payload);
          },
          [&event](const AllocationEvent& payload) { validate_allocation(event.header, payload); },
          [&event](const ReallocationEvent& payload) {
            validate_reallocation(event.header, payload);
          },
          [&event](const FreeEvent& payload) { validate_free(event.header, payload); },
          [&event](const VmAllocateEvent& payload) {
            validate_mapping_creation(event.header, payload.target, payload.mapping_id);
          },
          [&event](const VmFreeEvent& payload) {
            validate_mapping_end(event.header, payload.target, payload.mapping_id);
          },
          [&event](const MapEvent& payload) {
            validate_mapping_creation(event.header, payload.target, payload.mapping_id);
          },
          [&event](const UnmapEvent& payload) {
            validate_mapping_end(event.header, payload.target, payload.mapping_id);
          },
      },
      event.payload);
}

}  // namespace noleax::trace
