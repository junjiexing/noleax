#include "noleax/agent/linux/agent_memory.hpp"

#include <sys/mman.h>
#include <unistd.h>

#include <algorithm>
#include <bit>
#include <cerrno>
#include <cstring>
#include <limits>
#include <utility>

namespace noleax::agent::linux {
namespace {

[[nodiscard]] std::uint64_t page_size() noexcept {
  static const std::uint64_t cached = [] {
    const long value = ::sysconf(_SC_PAGESIZE);
    return value > 0 ? static_cast<std::uint64_t>(value) : 4096U;
  }();
  return cached;
}

void checked_add_category_bytes(std::uint64_t& total, std::uint64_t value) {
  if (value > std::numeric_limits<std::uint64_t>::max() - total) {
    throw AgentMemoryError{"agent memory category byte total overflow"};
  }
  total += value;
}

}  // namespace

void AgentMemoryRegistry::register_region(noleax::trace::AgentMemoryCategory category, void* base,
                                          std::size_t bytes) {
  std::scoped_lock lock{mutex_};
  if (region_count_ == regions_.size()) {
    throw AgentMemoryError{"agent memory region registry is full"};
  }
  regions_[region_count_] = Region{base, static_cast<std::uint64_t>(bytes), category};
  ++region_count_;
}

void AgentMemoryRegistry::unregister_region(void* base) noexcept {
  std::scoped_lock lock{mutex_};
  for (std::size_t index = 0U; index < region_count_; ++index) {
    if (regions_[index].base == base) {
      regions_[index] = regions_[region_count_ - 1U];
      --region_count_;
      return;
    }
  }
}

void AgentMemoryRegistry::set_estimate(noleax::trace::AgentMemoryCategory category,
                                       std::uint64_t reserved_bytes,
                                       std::uint64_t resident_bytes) noexcept {
  const std::size_t slot = static_cast<std::size_t>(category);
  if (slot >= estimates_.size()) {
    return;
  }
  std::scoped_lock lock{mutex_};
  estimates_[slot] = EstimateSlot{reserved_bytes, resident_bytes, true};
}

void AgentMemoryRegistry::clear_estimate(noleax::trace::AgentMemoryCategory category) noexcept {
  const std::size_t slot = static_cast<std::size_t>(category);
  if (slot >= estimates_.size()) {
    return;
  }
  std::scoped_lock lock{mutex_};
  estimates_[slot] = EstimateSlot{};
}

std::uint64_t AgentMemoryRegistry::measured_resident_bytes(const void* base,
                                                           std::uint64_t bytes) noexcept {
  const std::uint64_t pages = (bytes + page_size() - 1U) / page_size();
  try {
    if (residency_scratch_.size() < pages) {
      residency_scratch_.resize(static_cast<std::size_t>(pages));
    }
  } catch (...) {
    return 0U;  // a measurement hiccup reports 0 rather than failing the capture
  }
  if (::mincore(const_cast<void*>(base), static_cast<std::size_t>(bytes),
                residency_scratch_.data()) != 0) {
    return 0U;
  }
  std::uint64_t resident = 0U;
  for (std::uint64_t page = 0U; page < pages; ++page) {
    resident += (residency_scratch_[static_cast<std::size_t>(page)] & 1U) != 0U ? 1U : 0U;
  }
  return resident * page_size();
}

std::uint64_t AgentMemoryRegistry::region_resident_bytes(const void* base) noexcept {
  std::scoped_lock lock{mutex_};
  for (std::size_t index = 0U; index < region_count_; ++index) {
    if (regions_[index].base == base) {
      return measured_resident_bytes(regions_[index].base, regions_[index].bytes);
    }
  }
  return 0U;
}

std::uint64_t AgentMemoryRegistry::region_reserved_bytes(
    noleax::trace::AgentMemoryCategory category) const noexcept {
  std::scoped_lock lock{mutex_};
  std::uint64_t reserved = 0U;
  for (std::size_t index = 0U; index < region_count_; ++index) {
    if (regions_[index].category == category) {
      if (regions_[index].bytes > std::numeric_limits<std::uint64_t>::max() - reserved) {
        return std::numeric_limits<std::uint64_t>::max();
      }
      reserved += regions_[index].bytes;
    }
  }
  return reserved;
}

void AgentMemoryRegistry::snapshot(
    std::vector<noleax::trace::AgentMemoryCategorySample>& categories) {
  std::scoped_lock lock{mutex_};
  for (std::size_t index = 0U; index < region_count_; ++index) {
    noleax::trace::AgentMemoryCategorySample sample;
    sample.category = regions_[index].category;
    sample.flags = noleax::trace::kAgentMemoryCategoryFlagExact;
    sample.reserved_bytes = regions_[index].bytes;
    sample.resident_bytes = measured_resident_bytes(regions_[index].base, regions_[index].bytes);
    categories.push_back(sample);
  }
  for (std::size_t slot = 0U; slot < estimates_.size(); ++slot) {
    if (!estimates_[slot].present) {
      continue;
    }
    noleax::trace::AgentMemoryCategorySample sample;
    sample.category = static_cast<noleax::trace::AgentMemoryCategory>(slot);
    sample.flags = 0U;  // heap-backed estimate, never exact
    sample.reserved_bytes = estimates_[slot].reserved_bytes;
    sample.resident_bytes = estimates_[slot].resident_bytes;
    categories.push_back(sample);
  }
  // Merge categories that received both a measured region and an estimate: the record
  // carries one entry per category, exact only when every contribution was measured.
  for (std::size_t first = 0U; first < categories.size(); ++first) {
    for (std::size_t second = first + 1U; second < categories.size();) {
      if (categories[second].category != categories[first].category) {
        ++second;
        continue;
      }
      checked_add_category_bytes(categories[first].reserved_bytes,
                                 categories[second].reserved_bytes);
      checked_add_category_bytes(categories[first].resident_bytes,
                                 categories[second].resident_bytes);
      categories[first].flags &= categories[second].flags;
      categories.erase(categories.begin() + static_cast<std::ptrdiff_t>(second));
    }
  }
  std::sort(categories.begin(), categories.end(),
            [](const auto& left, const auto& right) { return left.category < right.category; });
}

EventQueuePlan plan_event_queue(std::uint64_t requested_bytes) {
  // One shared conversion: the runtime used to inline bit_floor(min(buffer_size /
  // sizeof(event), cap)) and report nothing (the SCL field incident, H4).
  constexpr std::uint64_t kMaximumCapacity = 1U << 24U;
  EventQueuePlan plan;
  const std::uint64_t requested_slots =
      (std::max)(std::uint64_t{2U}, requested_bytes / sizeof(LinuxHeapEvent));
  const std::uint64_t slots = std::bit_floor((std::min)(requested_slots, kMaximumCapacity));
  plan.capacity = static_cast<std::size_t>(slots);
  noleax::trace::BufferConfiguration& configuration = plan.configuration;
  configuration.requested_bytes = requested_bytes;
  configuration.effective_slots = slots;
  configuration.event_size = sizeof(LinuxHeapEvent);
  configuration.slot_size = LinuxHeapEventQueue::slot_size();
  configuration.reserved_bytes = slots * configuration.slot_size;
  configuration.resident_after_init_bytes = 0U;  // measured by the caller after creation
  configuration.flags =
      slots != requested_slots ? noleax::trace::kBufferConfigurationFlagAdjusted : 0U;
  return plan;
}

std::unique_ptr<LinuxHeapEventQueue> make_linux_heap_event_queue(std::size_t capacity) {
  // Compute the mapping size before touching anything; an overflow or mmap failure must
  // surface as AgentMemoryError, never as a bad_alloc escaping into target code.
  const std::size_t slot_size = LinuxHeapEventQueue::slot_size();
  if (capacity != 0U && capacity > static_cast<std::size_t>(-1) / slot_size) {
    throw AgentMemoryError{"event queue slot array size overflows"};
  }
  const std::size_t bytes = capacity * slot_size;
  void* const base =
      ::mmap(nullptr, bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (base == MAP_FAILED) {
    throw AgentMemoryError{"event queue mapping failed: " + std::string{std::strerror(errno)},
                           static_cast<std::uint32_t>(errno)};
  }
  try {
    AgentMemoryRegistry::instance().register_region(noleax::trace::AgentMemoryCategory::kEventQueue,
                                                    base, bytes);
  } catch (...) {
    ::munmap(base, bytes);
    throw;
  }
  try {
    return std::make_unique<LinuxHeapEventQueue>(
        capacity, base, [](void* slots, std::size_t slot_bytes) noexcept {
          AgentMemoryRegistry::instance().unregister_region(slots);
          ::munmap(slots, slot_bytes);
        });
  } catch (...) {
    AgentMemoryRegistry::instance().unregister_region(base);
    ::munmap(base, bytes);
    throw;
  }
}

}  // namespace noleax::agent::linux
