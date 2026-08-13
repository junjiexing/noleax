#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "noleax/agent/windows/stack_capture.hpp"
#include "noleax/trace/identifiers.hpp"
#include "noleax/trace/stack.hpp"

namespace noleax::agent::windows {

struct RawStackInternResult {
  noleax::trace::StackId stack_id;
  bool inserted{false};
  bool segment_reset{false};
};

[[nodiscard]] std::uint64_t hash_captured_stack(const CapturedStack& stack) noexcept;

class RawStackDictionary final {
 public:
  explicit RawStackDictionary(std::size_t maximum_entries);

  RawStackDictionary(const RawStackDictionary&) = delete;
  RawStackDictionary& operator=(const RawStackDictionary&) = delete;
  RawStackDictionary(RawStackDictionary&&) = delete;
  RawStackDictionary& operator=(RawStackDictionary&&) = delete;

  [[nodiscard]] RawStackInternResult intern(const CapturedStack& stack,
                                            std::uint64_t precomputed_hash);
  [[nodiscard]] std::size_t size() const noexcept;
  [[nodiscard]] std::size_t capacity() const noexcept;
  [[nodiscard]] std::uint64_t segment_count() const noexcept;
  // Backing-store footprint (entries + buckets). The vectors are constructed at full
  // size, so these bytes are committed at construction (H4 agent-memory accounting).
  [[nodiscard]] std::size_t storage_bytes() const noexcept;

 private:
  struct Entry {
    CapturedStack stack;
    noleax::trace::StackId stack_id;
    std::uint64_t hash{0U};
    std::uint32_t next_index{0U};
  };

  void reset_segment() noexcept;

  std::vector<Entry> entries_;
  std::vector<std::uint32_t> buckets_;
  std::size_t entry_count_{0U};
  std::uint64_t next_stack_id_{1U};
  std::uint64_t segment_count_{1U};
};

struct NormalizedStack {
  std::array<noleax::trace::StackFrame, kMaximumCapturedStackDepth> frames{};
  std::uint16_t frame_count{0U};
  noleax::trace::StackCaptureStatus status{noleax::trace::StackCaptureStatus::kUnavailable};

  bool operator==(const NormalizedStack&) const = default;
};

[[nodiscard]] std::uint64_t hash_normalized_stack(const NormalizedStack& stack) noexcept;

class NormalizedStackDictionary final {
 public:
  explicit NormalizedStackDictionary(std::size_t maximum_entries);

  NormalizedStackDictionary(const NormalizedStackDictionary&) = delete;
  NormalizedStackDictionary& operator=(const NormalizedStackDictionary&) = delete;
  NormalizedStackDictionary(NormalizedStackDictionary&&) = delete;
  NormalizedStackDictionary& operator=(NormalizedStackDictionary&&) = delete;

  [[nodiscard]] RawStackInternResult intern(const NormalizedStack& stack,
                                            std::uint64_t precomputed_hash);
  [[nodiscard]] std::size_t size() const noexcept;
  [[nodiscard]] std::size_t capacity() const noexcept;
  [[nodiscard]] std::uint64_t segment_count() const noexcept;
  // Backing-store footprint (entries + buckets). The vectors are constructed at full
  // size, so these bytes are committed at construction (H4 agent-memory accounting).
  [[nodiscard]] std::size_t storage_bytes() const noexcept;

 private:
  struct Entry {
    NormalizedStack stack;
    noleax::trace::StackId stack_id;
    std::uint64_t hash{0U};
    std::uint32_t next_index{0U};
  };

  void reset_segment() noexcept;

  std::vector<Entry> entries_;
  std::vector<std::uint32_t> buckets_;
  std::size_t entry_count_{0U};
  std::uint64_t next_stack_id_{1U};
  std::uint64_t segment_count_{1U};
};

}  // namespace noleax::agent::windows
