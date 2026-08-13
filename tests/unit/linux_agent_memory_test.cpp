// H4 (P0-1): the agent memory registry (mincore-measured dedicated regions + heap
// estimates), the buffer_size → slot conversion math, and the lazy-commit contract of
// the mmap-backed event queue (untouched pages stay uncommitted across construction and
// reset_quiescent).

#include <sys/mman.h>
#include <unistd.h>

#include <atomic>
#include <catch2/catch_test_macros.hpp>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <thread>
#include <vector>

#include "noleax/agent/linux/agent_memory.hpp"
#include "noleax/agent/linux/heap_event.hpp"
#include "noleax/trace/memory_snapshot.hpp"

namespace {

using noleax::agent::linux::AgentMemoryRegistry;
using noleax::agent::linux::LinuxHeapEventQueue;
using noleax::agent::linux::make_linux_heap_event_queue;
using noleax::agent::linux::plan_event_queue;

[[nodiscard]] std::uint64_t resident_set_bytes() {
  std::FILE* const statm = std::fopen("/proc/self/statm", "re");
  REQUIRE(statm != nullptr);
  unsigned long long total_pages = 0U;
  unsigned long long resident_pages = 0U;
  const int fields = std::fscanf(statm, "%llu %llu", &total_pages, &resident_pages);
  std::fclose(statm);
  REQUIRE(fields == 2);
  return resident_pages * static_cast<std::uint64_t>(::sysconf(_SC_PAGESIZE));
}

[[nodiscard]] const noleax::trace::AgentMemoryCategorySample* find_category(
    const std::vector<noleax::trace::AgentMemoryCategorySample>& categories,
    noleax::trace::AgentMemoryCategory category) {
  for (const auto& sample : categories) {
    if (sample.category == category) {
      return &sample;
    }
  }
  return nullptr;
}

// Removes everything the test registered, even on failure (the registry is process-global).
struct RegionGuard {
  ~RegionGuard() {
    if (base != nullptr) {
      AgentMemoryRegistry::instance().unregister_region(base);
      ::munmap(base, bytes);
    }
    AgentMemoryRegistry::instance().clear_estimate(noleax::trace::AgentMemoryCategory::kAgentHeap);
  }
  void* base{nullptr};
  std::size_t bytes{0U};
};

TEST_CASE("event queue plan reports the exact slot math", "[agent][memory][linux]") {
  // The field-incident request: 8 GiB silently became 8,388,608 fixed slots.
  const auto plan = plan_event_queue(8ULL * 1024U * 1024U * 1024U);
  CHECK(plan.capacity == 8'388'608U);
  CHECK(plan.configuration.requested_bytes == 8ULL * 1024U * 1024U * 1024U);
  CHECK(plan.configuration.effective_slots == 8'388'608U);
  CHECK(plan.configuration.event_size == 648U);
  CHECK(plan.configuration.slot_size == 656U);
  CHECK(plan.configuration.reserved_bytes == 8'388'608ULL * 656U);
  CHECK((plan.configuration.flags & noleax::trace::kBufferConfigurationFlagAdjusted) != 0U);
  noleax::trace::validate_buffer_configuration(plan.configuration);

  // The default 16 MiB buffer floors to 16384 slots and is an adjustment too.
  const auto default_plan = plan_event_queue(16U * 1024U * 1024U);
  CHECK(default_plan.capacity == 16'384U);
  CHECK((default_plan.configuration.flags & noleax::trace::kBufferConfigurationFlagAdjusted) != 0U);

  // An exact power-of-two slot count survives unadjusted.
  const auto exact_plan = plan_event_queue(16'384ULL * 648ULL);
  CHECK(exact_plan.capacity == 16'384U);
  CHECK((exact_plan.configuration.flags & noleax::trace::kBufferConfigurationFlagAdjusted) == 0U);

  // The capacity cap is an adjustment as well.
  const auto capped_plan = plan_event_queue(1024ULL * 1024U * 1024U * 1024U);
  CHECK(capped_plan.capacity == (1U << 24U));
  CHECK((capped_plan.configuration.flags & noleax::trace::kBufferConfigurationFlagAdjusted) != 0U);
}

TEST_CASE("agent memory registry measures region residency exactly", "[agent][memory][linux]") {
  const std::uint64_t page = static_cast<std::uint64_t>(::sysconf(_SC_PAGESIZE));
  constexpr std::size_t kBytes = 16U * 1024U * 1024U;
  RegionGuard guard;
  guard.base = ::mmap(nullptr, kBytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  REQUIRE(guard.base != MAP_FAILED);
  guard.bytes = kBytes;
  AgentMemoryRegistry::instance().register_region(noleax::trace::AgentMemoryCategory::kEventQueue,
                                                  guard.base, kBytes);

  std::vector<noleax::trace::AgentMemoryCategorySample> categories;
  AgentMemoryRegistry::instance().snapshot(categories);
  const auto* queue = find_category(categories, noleax::trace::AgentMemoryCategory::kEventQueue);
  REQUIRE(queue != nullptr);
  CHECK(queue->reserved_bytes == kBytes);
  CHECK(queue->resident_bytes == 0U);
  CHECK((queue->flags & noleax::trace::kAgentMemoryCategoryFlagExact) != 0U);

  // Touch one page per MiB spread across the region: exactly those pages become resident.
  constexpr std::uint64_t kTouchedPages = 16U;
  for (std::uint64_t index = 0U; index < kTouchedPages; ++index) {
    static_cast<volatile std::uint8_t*>(guard.base)[index * 1024U * 1024U] = 0xABU;
  }
  categories.clear();
  AgentMemoryRegistry::instance().snapshot(categories);
  queue = find_category(categories, noleax::trace::AgentMemoryCategory::kEventQueue);
  REQUIRE(queue != nullptr);
  CHECK(queue->resident_bytes == kTouchedPages * page);
  CHECK(AgentMemoryRegistry::instance().region_resident_bytes(guard.base) == kTouchedPages * page);

  // A heap estimate for the same category merges in and drops the exact flag.
  AgentMemoryRegistry::instance().set_estimate(noleax::trace::AgentMemoryCategory::kEventQueue,
                                               4U * 1024U, 4U * 1024U);
  categories.clear();
  AgentMemoryRegistry::instance().snapshot(categories);
  queue = find_category(categories, noleax::trace::AgentMemoryCategory::kEventQueue);
  REQUIRE(queue != nullptr);
  CHECK(queue->reserved_bytes == kBytes + 4U * 1024U);
  CHECK(queue->resident_bytes == kTouchedPages * page + 4U * 1024U);
  CHECK((queue->flags & noleax::trace::kAgentMemoryCategoryFlagExact) == 0U);
  AgentMemoryRegistry::instance().clear_estimate(noleax::trace::AgentMemoryCategory::kEventQueue);

  AgentMemoryRegistry::instance().set_estimate(noleax::trace::AgentMemoryCategory::kAgentHeap,
                                               9U * 1024U * 1024U, 512U * 1024U);
  categories.clear();
  AgentMemoryRegistry::instance().snapshot(categories);
  const auto* heap = find_category(categories, noleax::trace::AgentMemoryCategory::kAgentHeap);
  REQUIRE(heap != nullptr);
  CHECK(heap->reserved_bytes == 9U * 1024U * 1024U);
  CHECK(heap->resident_bytes == 512U * 1024U);
  CHECK((heap->flags & noleax::trace::kAgentMemoryCategoryFlagExact) == 0U);
}

TEST_CASE("mmap event queue commits pages lazily across construction and reset",
          "[agent][memory][linux]") {
  // 2^21 slots x 656 B = 1.34 GiB reserved; construction must commit (almost) nothing.
  constexpr std::size_t kCapacity = 1U << 21U;
  const std::uint64_t before = resident_set_bytes();
  auto queue = make_linux_heap_event_queue(kCapacity);
  const std::uint64_t after_construct = resident_set_bytes();
  CHECK(after_construct - before < 4U * 1024U * 1024U);

  std::vector<noleax::trace::AgentMemoryCategorySample> categories;
  AgentMemoryRegistry::instance().snapshot(categories);
  const auto* sample = find_category(categories, noleax::trace::AgentMemoryCategory::kEventQueue);
  REQUIRE(sample != nullptr);
  CHECK(sample->reserved_bytes == kCapacity * LinuxHeapEventQueue::slot_size());
  CHECK(sample->resident_bytes < 4U * 1024U * 1024U);

  // Fill half the ring: exactly the touched half commits.
  noleax::agent::linux::LinuxHeapEvent event{};
  for (std::size_t index = 0U; index < kCapacity / 2U; ++index) {
    REQUIRE(queue->try_push(event));
  }
  categories.clear();
  AgentMemoryRegistry::instance().snapshot(categories);
  sample = find_category(categories, noleax::trace::AgentMemoryCategory::kEventQueue);
  REQUIRE(sample != nullptr);
  CHECK(sample->resident_bytes >= 512U * 1024U * 1024U);
  CHECK(sample->resident_bytes < kCapacity * LinuxHeapEventQueue::slot_size());

  // Draining and resetting must not commit the untouched half either.
  noleax::agent::linux::LinuxHeapEvent popped{};
  while (queue->try_pop(popped)) {
  }
  queue->reset_quiescent();
  categories.clear();
  AgentMemoryRegistry::instance().snapshot(categories);
  sample = find_category(categories, noleax::trace::AgentMemoryCategory::kEventQueue);
  REQUIRE(sample != nullptr);
  CHECK(sample->resident_bytes < kCapacity * LinuxHeapEventQueue::slot_size());

  // The reset queue is fully functional again, with sequences restarting at 1.
  const auto stamp = [](noleax::agent::linux::LinuxHeapEvent& destination,
                        std::uint64_t sequence) noexcept { destination.queue_sequence = sequence; };
  for (std::size_t index = 0U; index < 1024U; ++index) {
    REQUIRE(queue->try_emplace(stamp));
  }
  for (std::size_t index = 0U; index < 1024U; ++index) {
    REQUIRE(queue->try_pop(popped));
    CHECK(popped.queue_sequence == index + 1U);
  }
}

TEST_CASE("agent memory registry rejects overflow with a stable error", "[agent][memory][linux]") {
  // The region table is fixed-size (no allocation after construction, so registration can
  // never bad_alloc into target code); overflow is a dedicated AgentMemoryError.
  constexpr std::size_t kMaximumRegions = 8U;
  std::vector<void*> bases;
  for (std::size_t index = 0U; index < kMaximumRegions; ++index) {
    void* const base =
        ::mmap(nullptr, 4096U, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(base != MAP_FAILED);
    bases.push_back(base);
    AgentMemoryRegistry::instance().register_region(noleax::trace::AgentMemoryCategory::kEventQueue,
                                                    base, 4096U);
  }
  void* const extra =
      ::mmap(nullptr, 4096U, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  REQUIRE(extra != MAP_FAILED);
  CHECK_THROWS_AS(AgentMemoryRegistry::instance().register_region(
                      noleax::trace::AgentMemoryCategory::kEventQueue, extra, 4096U),
                  noleax::agent::linux::AgentMemoryError);
  for (void* const base : bases) {
    AgentMemoryRegistry::instance().unregister_region(base);
    ::munmap(base, 4096U);
  }
  ::munmap(extra, 4096U);
}

TEST_CASE("mmap event queue keeps MPSC semantics under concurrency", "[agent][memory][linux]") {
  constexpr std::size_t kCapacity = 1U << 14U;
  auto queue = make_linux_heap_event_queue(kCapacity);
  constexpr std::size_t kProducers = 4U;
  constexpr std::size_t kEventsPerProducer = 2'000U;
  std::atomic<bool> start{false};
  std::vector<std::thread> producers;
  for (std::size_t producer = 0U; producer < kProducers; ++producer) {
    producers.emplace_back([&queue, &start] {
      while (!start.load(std::memory_order_acquire)) {
      }
      for (std::size_t index = 0U; index < kEventsPerProducer; ++index) {
        while (!queue->try_emplace(
            [](noleax::agent::linux::LinuxHeapEvent& destination, std::uint64_t sequence) noexcept {
              destination.queue_sequence = sequence;
            })) {
        }
      }
    });
  }
  start.store(true, std::memory_order_release);
  std::uint64_t sequence_floor = 0U;
  noleax::agent::linux::LinuxHeapEvent event{};
  std::size_t consumed = 0U;
  while (consumed < kProducers * kEventsPerProducer) {
    if (queue->try_pop(event)) {
      CHECK(event.queue_sequence > sequence_floor);
      sequence_floor = event.queue_sequence;
      ++consumed;
    }
  }
  for (auto& producer : producers) {
    producer.join();
  }
  CHECK(queue->dropped_count() == 0U);
}

}  // namespace
