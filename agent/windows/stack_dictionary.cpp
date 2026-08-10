#include "noleax/agent/windows/stack_dictionary.hpp"

#include <algorithm>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>

namespace noleax::agent::windows {
namespace {

inline constexpr std::uint32_t kEmptyIndex = std::numeric_limits<std::uint32_t>::max();
inline constexpr std::uint64_t kFnvOffsetBasis = 14695981039346656037ULL;
inline constexpr std::uint64_t kFnvPrime = 1099511628211ULL;

void hash_byte(std::uint64_t& hash, std::uint8_t value) noexcept {
  hash ^= value;
  hash *= kFnvPrime;
}

void hash_u64(std::uint64_t& hash, std::uint64_t value) noexcept {
  for (std::uint32_t shift = 0U; shift < 64U; shift += 8U) {
    hash_byte(hash, static_cast<std::uint8_t>((value >> shift) & 0xFFU));
  }
}

[[nodiscard]] std::size_t bucket_count_for(std::size_t maximum_entries) {
  const std::size_t maximum_power_of_two = std::bit_floor(std::numeric_limits<std::size_t>::max());
  if (maximum_entries == 0U ||
      maximum_entries > static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max()) ||
      maximum_entries > maximum_power_of_two / 2U) {
    throw std::invalid_argument{"stack dictionary capacity is out of range"};
  }
  return std::bit_ceil(maximum_entries * 2U);
}

[[nodiscard]] std::size_t validated_entry_count(std::size_t maximum_entries) {
  static_cast<void>(bucket_count_for(maximum_entries));
  return maximum_entries;
}

void validate_interned_stack(const CapturedStack& stack) {
  if (!stack_capture_succeeded(stack)) {
    throw std::invalid_argument{"stack dictionary requires a successful captured stack"};
  }
  for (std::uint16_t index = 0U; index < stack.frame_count; ++index) {
    if (stack.frames[index] == 0U) {
      throw std::invalid_argument{"stack dictionary requires nonzero frame addresses"};
    }
  }
}

void validate_interned_stack(const NormalizedStack& stack) {
  const bool successful = stack.status == noleax::trace::StackCaptureStatus::kComplete ||
                          stack.status == noleax::trace::StackCaptureStatus::kTruncatedByDepth;
  if (!successful || stack.frame_count == 0U || stack.frame_count > kMaximumCapturedStackDepth) {
    throw std::invalid_argument{"normalized stack dictionary requires a successful stack"};
  }
  for (std::uint16_t index = 0U; index < stack.frame_count; ++index) {
    const auto& frame = stack.frames[index];
    if (frame.absolute_address == 0U || (!frame.module_id && frame.module_offset != 0U) ||
        frame.flags != 0U) {
      throw std::invalid_argument{"normalized stack dictionary frame is invalid"};
    }
  }
}

[[nodiscard]] bool same_stack(const CapturedStack& left, const CapturedStack& right) noexcept {
  return left.status == right.status && left.frame_count == right.frame_count &&
         std::equal(left.frames.begin(), left.frames.begin() + left.frame_count,
                    right.frames.begin());
}

[[nodiscard]] bool same_stack(const NormalizedStack& left, const NormalizedStack& right) noexcept {
  return left.status == right.status && left.frame_count == right.frame_count &&
         std::equal(left.frames.begin(), left.frames.begin() + left.frame_count,
                    right.frames.begin());
}

}  // namespace

std::uint64_t hash_captured_stack(const CapturedStack& stack) noexcept {
  std::uint64_t hash = kFnvOffsetBasis;
  hash_byte(hash, static_cast<std::uint8_t>(stack.status));
  hash_u64(hash, stack.frame_count);
  const std::uint16_t frame_count = (std::min)(stack.frame_count, kMaximumCapturedStackDepth);
  for (std::uint16_t index = 0U; index < frame_count; ++index) {
    hash_u64(hash, stack.frames[index]);
  }
  return hash;
}

std::uint64_t hash_normalized_stack(const NormalizedStack& stack) noexcept {
  std::uint64_t hash = kFnvOffsetBasis;
  hash_byte(hash, static_cast<std::uint8_t>(stack.status));
  hash_u64(hash, stack.frame_count);
  const std::uint16_t frame_count = (std::min)(stack.frame_count, kMaximumCapturedStackDepth);
  for (std::uint16_t index = 0U; index < frame_count; ++index) {
    const auto& frame = stack.frames[index];
    hash_u64(hash, frame.module_id.value());
    hash_u64(hash, frame.module_offset);
    hash_u64(hash, frame.absolute_address);
    hash_u64(hash, frame.flags);
  }
  return hash;
}

RawStackDictionary::RawStackDictionary(std::size_t maximum_entries)
    : entries_(validated_entry_count(maximum_entries)),
      buckets_(bucket_count_for(maximum_entries), kEmptyIndex) {}

RawStackInternResult RawStackDictionary::intern(const CapturedStack& stack,
                                                std::uint64_t precomputed_hash) {
  validate_interned_stack(stack);
  bool segment_reset = false;
  std::size_t bucket = static_cast<std::size_t>(precomputed_hash) & (buckets_.size() - 1U);
  for (std::uint32_t index = buckets_[bucket]; index != kEmptyIndex;
       index = entries_[index].next_index) {
    const Entry& entry = entries_[index];
    if (entry.hash == precomputed_hash && same_stack(entry.stack, stack)) {
      return {entry.stack_id, false, false};
    }
  }

  if (entry_count_ == entries_.size()) {
    reset_segment();
    segment_reset = true;
    bucket = static_cast<std::size_t>(precomputed_hash) & (buckets_.size() - 1U);
  }
  if (next_stack_id_ == std::numeric_limits<std::uint64_t>::max()) {
    throw std::overflow_error{"stack ID space is exhausted"};
  }

  Entry& entry = entries_[entry_count_];
  entry.stack = stack;
  entry.stack_id = noleax::trace::StackId{next_stack_id_++};
  entry.hash = precomputed_hash;
  entry.next_index = buckets_[bucket];
  buckets_[bucket] = static_cast<std::uint32_t>(entry_count_);
  ++entry_count_;
  return {entry.stack_id, true, segment_reset};
}

std::size_t RawStackDictionary::size() const noexcept { return entry_count_; }

std::size_t RawStackDictionary::capacity() const noexcept { return entries_.size(); }

std::uint64_t RawStackDictionary::segment_count() const noexcept { return segment_count_; }

void RawStackDictionary::reset_segment() noexcept {
  std::fill(buckets_.begin(), buckets_.end(), kEmptyIndex);
  entry_count_ = 0U;
  if (segment_count_ != std::numeric_limits<std::uint64_t>::max()) {
    ++segment_count_;
  }
}

NormalizedStackDictionary::NormalizedStackDictionary(std::size_t maximum_entries)
    : entries_(validated_entry_count(maximum_entries)),
      buckets_(bucket_count_for(maximum_entries), kEmptyIndex) {}

RawStackInternResult NormalizedStackDictionary::intern(const NormalizedStack& stack,
                                                       std::uint64_t precomputed_hash) {
  validate_interned_stack(stack);
  bool segment_reset = false;
  std::size_t bucket = static_cast<std::size_t>(precomputed_hash) & (buckets_.size() - 1U);
  for (std::uint32_t index = buckets_[bucket]; index != kEmptyIndex;
       index = entries_[index].next_index) {
    const Entry& entry = entries_[index];
    if (entry.hash == precomputed_hash && same_stack(entry.stack, stack)) {
      return {entry.stack_id, false, false};
    }
  }

  if (entry_count_ == entries_.size()) {
    reset_segment();
    segment_reset = true;
    bucket = static_cast<std::size_t>(precomputed_hash) & (buckets_.size() - 1U);
  }
  if (next_stack_id_ == std::numeric_limits<std::uint64_t>::max()) {
    throw std::overflow_error{"stack ID space is exhausted"};
  }

  Entry& entry = entries_[entry_count_];
  entry.stack = stack;
  entry.stack_id = noleax::trace::StackId{next_stack_id_++};
  entry.hash = precomputed_hash;
  entry.next_index = buckets_[bucket];
  buckets_[bucket] = static_cast<std::uint32_t>(entry_count_);
  ++entry_count_;
  return {entry.stack_id, true, segment_reset};
}

std::size_t NormalizedStackDictionary::size() const noexcept { return entry_count_; }

std::size_t NormalizedStackDictionary::capacity() const noexcept { return entries_.size(); }

std::uint64_t NormalizedStackDictionary::segment_count() const noexcept { return segment_count_; }

void NormalizedStackDictionary::reset_segment() noexcept {
  std::fill(buckets_.begin(), buckets_.end(), kEmptyIndex);
  entry_count_ = 0U;
  if (segment_count_ != std::numeric_limits<std::uint64_t>::max()) {
    ++segment_count_;
  }
}

}  // namespace noleax::agent::windows

#if !defined(_WIN32)
namespace noleax::agent::windows {

// Link shim for non-Windows builds: stack_capture.cpp (which defines this on Windows)
// is Windows-only, while this dictionary is platform-neutral. The body mirrors the
// Windows definition exactly; the POD layout is identical on both platforms. Hoisting
// the dictionary to the shared namespace is deferred to a Windows-CI-verified change.
bool stack_capture_succeeded(const CapturedStack& stack) noexcept {
  return (stack.status == StackCaptureStatus::kCaptured ||
          stack.status == StackCaptureStatus::kTruncated) &&
         stack.frame_count != 0U && stack.frame_count <= stack.requested_depth &&
         stack.requested_depth <= kMaximumCapturedStackDepth;
}

}  // namespace noleax::agent::windows
#endif
