#include "noleax/agent/bounded_mpsc_queue.hpp"

#include <array>
#include <atomic>
#include <catch2/catch_test_macros.hpp>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <thread>
#include <vector>

namespace {

struct QueueEvent {
  std::uint64_t queue_sequence{0U};
  std::uint32_t producer{0U};
  std::uint32_t producer_sequence{0U};
  std::uint64_t checksum{0U};
};

[[nodiscard]] constexpr std::uint64_t event_checksum(std::uint32_t producer,
                                                     std::uint32_t sequence) noexcept {
  return (static_cast<std::uint64_t>(producer) << 32U) |
         static_cast<std::uint64_t>(sequence ^ 0xa5a55a5aU);
}

}  // namespace

TEST_CASE("bounded MPSC queue validates and reports its fixed capacity", "[agent][mpsc]") {
  CHECK_THROWS_AS(noleax::agent::BoundedMpscQueue<QueueEvent>{0U}, std::invalid_argument);
  CHECK_THROWS_AS(noleax::agent::BoundedMpscQueue<QueueEvent>{1U}, std::invalid_argument);
  CHECK_THROWS_AS(noleax::agent::BoundedMpscQueue<QueueEvent>{3U}, std::invalid_argument);

  const noleax::agent::BoundedMpscQueue<QueueEvent> queue{8U};
  CHECK(queue.capacity() == 8U);
  CHECK(queue.dropped_count() == 0U);
}

TEST_CASE("bounded MPSC queue preserves FIFO order across reuse and reset", "[agent][mpsc]") {
  noleax::agent::BoundedMpscQueue<QueueEvent> queue{4U};

  for (std::uint32_t round = 0U; round < 100U; ++round) {
    for (std::uint32_t index = 0U; index < 4U; ++index) {
      const QueueEvent event{0U, round, index, event_checksum(round, index)};
      REQUIRE(queue.try_push(event));
    }
    CHECK_FALSE(queue.try_push({}));

    for (std::uint32_t index = 0U; index < 4U; ++index) {
      QueueEvent event;
      REQUIRE(queue.try_pop(event));
      CHECK(event.producer == round);
      CHECK(event.producer_sequence == index);
      CHECK(event.checksum == event_checksum(round, index));
    }
    QueueEvent empty_event;
    CHECK_FALSE(queue.try_pop(empty_event));
  }

  CHECK(queue.dropped_count() == 100U);
  CHECK(queue.take_dropped_count() == 100U);
  CHECK(queue.take_dropped_count() == 0U);

  REQUIRE(queue.try_emplace([](QueueEvent& event, std::uint64_t queue_sequence) noexcept {
    event.queue_sequence = queue_sequence;
  }));
  QueueEvent event;
  REQUIRE(queue.try_pop(event));
  CHECK(event.queue_sequence == 401U);

  queue.reset_quiescent();
  REQUIRE(queue.try_emplace([](QueueEvent& reset_event, std::uint64_t queue_sequence) noexcept {
    reset_event.queue_sequence = queue_sequence;
  }));
  REQUIRE(queue.try_pop(event));
  CHECK(event.queue_sequence == 1U);
  CHECK(queue.dropped_count() == 0U);
}

TEST_CASE("bounded MPSC queue accepts concurrent producers without corruption", "[agent][mpsc]") {
  constexpr std::size_t kProducerCount = 8U;
  constexpr std::uint32_t kEventsPerProducer = 2'000U;
  constexpr std::size_t kTotalEvents = kProducerCount * kEventsPerProducer;
  noleax::agent::BoundedMpscQueue<QueueEvent> queue{16'384U};
  std::atomic<bool> start{false};
  std::atomic<bool> push_failed{false};
  std::array<std::thread, kProducerCount> producers;

  for (std::size_t producer = 0U; producer < kProducerCount; ++producer) {
    producers[producer] = std::thread{[&, producer] {
      while (!start.load(std::memory_order_acquire)) {
        std::this_thread::yield();
      }
      for (std::uint32_t index = 0U; index < kEventsPerProducer; ++index) {
        if (!queue.try_emplace(
                [producer, index](QueueEvent& event, std::uint64_t queue_sequence) noexcept {
                  event.queue_sequence = queue_sequence;
                  event.producer = static_cast<std::uint32_t>(producer);
                  event.producer_sequence = index;
                  event.checksum = event_checksum(event.producer, index);
                })) {
          push_failed.store(true, std::memory_order_release);
        }
      }
    }};
  }

  start.store(true, std::memory_order_release);
  for (auto& producer : producers) {
    producer.join();
  }

  REQUIRE_FALSE(push_failed.load(std::memory_order_acquire));
  CHECK(queue.dropped_count() == 0U);
  std::vector<bool> observed(kTotalEvents, false);
  for (std::uint64_t expected_queue_sequence = 1U; expected_queue_sequence <= kTotalEvents;
       ++expected_queue_sequence) {
    QueueEvent event;
    REQUIRE(queue.try_pop(event));
    REQUIRE(event.producer < kProducerCount);
    REQUIRE(event.producer_sequence < kEventsPerProducer);
    CHECK(event.queue_sequence == expected_queue_sequence);
    CHECK(event.checksum == event_checksum(event.producer, event.producer_sequence));
    const std::size_t identity =
        static_cast<std::size_t>(event.producer) * kEventsPerProducer + event.producer_sequence;
    CHECK_FALSE(observed[identity]);
    observed[identity] = true;
  }
  QueueEvent event;
  CHECK_FALSE(queue.try_pop(event));
}

TEST_CASE("bounded MPSC queue counts every nonblocking overflow", "[agent][mpsc]") {
  constexpr std::size_t kProducerCount = 8U;
  constexpr std::uint32_t kAttemptsPerProducer = 1'000U;
  constexpr std::uint64_t kAttemptCount = kProducerCount * kAttemptsPerProducer;
  constexpr std::size_t kCapacity = 256U;
  noleax::agent::BoundedMpscQueue<QueueEvent> queue{kCapacity};
  std::atomic<bool> start{false};
  std::atomic<std::uint64_t> accepted{0U};
  std::array<std::thread, kProducerCount> producers;

  for (std::size_t producer = 0U; producer < kProducerCount; ++producer) {
    producers[producer] = std::thread{[&, producer] {
      while (!start.load(std::memory_order_acquire)) {
        std::this_thread::yield();
      }
      for (std::uint32_t index = 0U; index < kAttemptsPerProducer; ++index) {
        if (queue.try_emplace(
                [producer, index](QueueEvent& event, std::uint64_t queue_sequence) noexcept {
                  event.queue_sequence = queue_sequence;
                  event.producer = static_cast<std::uint32_t>(producer);
                  event.producer_sequence = index;
                  event.checksum = event_checksum(event.producer, index);
                })) {
          accepted.fetch_add(1U, std::memory_order_relaxed);
        }
      }
    }};
  }

  start.store(true, std::memory_order_release);
  for (auto& producer : producers) {
    producer.join();
  }

  CHECK(accepted.load(std::memory_order_relaxed) == kCapacity);
  CHECK(queue.dropped_count() == kAttemptCount - kCapacity);
  for (std::uint64_t expected_queue_sequence = 1U; expected_queue_sequence <= kCapacity;
       ++expected_queue_sequence) {
    QueueEvent event;
    REQUIRE(queue.try_pop(event));
    CHECK(event.queue_sequence == expected_queue_sequence);
    CHECK(event.checksum == event_checksum(event.producer, event.producer_sequence));
  }
  QueueEvent event;
  CHECK_FALSE(queue.try_pop(event));
}

TEST_CASE("bounded MPSC queue publishes safely to a concurrent consumer", "[agent][mpsc]") {
  constexpr std::size_t kProducerCount = 8U;
  constexpr std::uint32_t kAttemptsPerProducer = 20'000U;
  constexpr std::uint64_t kAttemptCount = kProducerCount * kAttemptsPerProducer;
  noleax::agent::BoundedMpscQueue<QueueEvent> queue{1'024U};
  std::atomic<bool> start{false};
  std::atomic<std::size_t> finished_producers{0U};
  std::atomic<std::uint64_t> accepted{0U};
  std::atomic<bool> invalid_event{false};
  std::vector<bool> observed(kAttemptCount, false);
  std::uint64_t consumed = 0U;

  std::thread consumer{[&] {
    std::uint32_t idle_iterations = 0U;
    while (finished_producers.load(std::memory_order_acquire) != kProducerCount ||
           consumed != accepted.load(std::memory_order_acquire)) {
      QueueEvent event;
      if (!queue.try_pop(event)) {
        if (finished_producers.load(std::memory_order_acquire) == kProducerCount &&
            ++idle_iterations == 100'000U) {
          invalid_event.store(true, std::memory_order_release);
          break;
        }
        std::this_thread::yield();
        continue;
      }

      idle_iterations = 0U;
      ++consumed;
      if (event.queue_sequence != consumed || event.producer >= kProducerCount ||
          event.producer_sequence >= kAttemptsPerProducer ||
          event.checksum != event_checksum(event.producer, event.producer_sequence)) {
        invalid_event.store(true, std::memory_order_release);
        continue;
      }
      const std::size_t identity =
          static_cast<std::size_t>(event.producer) * kAttemptsPerProducer + event.producer_sequence;
      if (observed[identity]) {
        invalid_event.store(true, std::memory_order_release);
      }
      observed[identity] = true;
    }
  }};

  std::array<std::thread, kProducerCount> producers;
  for (std::size_t producer = 0U; producer < kProducerCount; ++producer) {
    producers[producer] = std::thread{[&, producer] {
      while (!start.load(std::memory_order_acquire)) {
        std::this_thread::yield();
      }
      for (std::uint32_t index = 0U; index < kAttemptsPerProducer; ++index) {
        if (queue.try_emplace(
                [producer, index](QueueEvent& event, std::uint64_t queue_sequence) noexcept {
                  event.queue_sequence = queue_sequence;
                  event.producer = static_cast<std::uint32_t>(producer);
                  event.producer_sequence = index;
                  event.checksum = event_checksum(event.producer, index);
                })) {
          accepted.fetch_add(1U, std::memory_order_release);
        }
      }
      finished_producers.fetch_add(1U, std::memory_order_release);
    }};
  }

  start.store(true, std::memory_order_release);
  for (auto& producer : producers) {
    producer.join();
  }
  consumer.join();

  CHECK_FALSE(invalid_event.load(std::memory_order_acquire));
  CHECK(consumed == accepted.load(std::memory_order_acquire));
  CHECK(queue.dropped_count() == kAttemptCount - consumed);
  QueueEvent event;
  CHECK_FALSE(queue.try_pop(event));
}

TEST_CASE("bounded MPSC queue reports live occupancy consumption and high water", "[agent][mpsc]") {
  noleax::agent::BoundedMpscQueue<QueueEvent> queue{8U};
  CHECK(queue.occupancy() == 0U);
  CHECK(queue.consumed_count() == 0U);
  CHECK(queue.high_water() == 0U);

  for (std::uint32_t index = 0U; index < 3U; ++index) {
    REQUIRE(queue.try_push(QueueEvent{0U, 0U, index, 0U}));
  }
  CHECK(queue.occupancy() == 3U);
  CHECK(queue.consumed_count() == 0U);

  QueueEvent event;
  REQUIRE(queue.try_pop(event));
  CHECK(queue.consumed_count() == 1U);
  CHECK(queue.occupancy() == 2U);
  CHECK(queue.high_water() == 3U);  // sampled at pop time, before the dequeue

  REQUIRE(queue.try_pop(event));
  REQUIRE(queue.try_pop(event));
  CHECK_FALSE(queue.try_pop(event));
  CHECK(queue.occupancy() == 0U);
  CHECK(queue.consumed_count() == 3U);
  CHECK(queue.high_water() == 3U);

  // A full ring pins the high water at the capacity through the drop path.
  for (std::uint32_t index = 0U; index < 8U; ++index) {
    REQUIRE(queue.try_push(QueueEvent{0U, 1U, index, 0U}));
  }
  CHECK(queue.occupancy() == 8U);
  CHECK_FALSE(queue.try_push(QueueEvent{}));
  CHECK(queue.high_water() == 8U);
  CHECK(queue.dropped_count() == 1U);

  std::uint64_t drained = 0U;
  while (queue.try_pop(event)) {
    ++drained;
  }
  CHECK(drained == 8U);
  CHECK(queue.consumed_count() == 11U);

  queue.reset_quiescent();
  CHECK(queue.occupancy() == 0U);
  CHECK(queue.consumed_count() == 0U);
  CHECK(queue.high_water() == 0U);
}
