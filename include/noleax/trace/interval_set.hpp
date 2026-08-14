#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <utility>
#include <vector>

namespace noleax::trace {

// Ordered set of pairwise non-overlapping half-open intervals [begin, end), each carrying a
// caller-defined value. The Linux agent's trace writer and the analyzer share this one
// implementation for virtual-memory mapping generations (docs/TRACE_WRITER.md), so the
// partial-free records the writer emits and the subtractions the analyzer applies agree bit
// for bit.
//
// Invariants: intervals are sorted by begin, pairwise non-overlapping, and begin < end.
// Intervals are NEVER coalesced, not even when adjacent with equal values: the writer and the
// analyzer apply the same operation stream to their own instances, and keeping every fragment
// boundary is what makes their states agree exactly at each record boundary.
//
// Ranges with begin >= end are no-ops everywhere; callers validate address arithmetic
// (overflow) before calling.
template <typename T>
class IntervalSet final {
 public:
  // One interval [begin, end) with its value. Query and mutation results are clipped to the
  // requested range where applicable.
  struct Fragment {
    std::uint64_t begin{0U};
    std::uint64_t end{0U};  // exclusive
    T value{};

    bool operator==(const Fragment&) const = default;
  };

  [[nodiscard]] bool empty() const noexcept { return intervals_.empty(); }

  // The number of stored intervals (a generation with a hole counts twice).
  [[nodiscard]] std::size_t size() const noexcept { return intervals_.size(); }

  // The sum of interval lengths.
  [[nodiscard]] std::uint64_t total_bytes() const noexcept {
    std::uint64_t total = 0U;
    for (const auto& [begin, entry] : intervals_) {
      total += entry.first - begin;
    }
    return total;
  }

  // Every stored interval, whole (not clipped), in address order.
  [[nodiscard]] std::vector<Fragment> fragments() const {
    std::vector<Fragment> result;
    result.reserve(intervals_.size());
    for (const auto& [begin, entry] : intervals_) {
      result.push_back(Fragment{begin, entry.first, entry.second});
    }
    return result;
  }

  // The interval containing point, if any.
  [[nodiscard]] std::optional<Fragment> find(std::uint64_t point) const {
    const auto it = candidate(point);
    if (it == intervals_.end()) {
      return std::nullopt;
    }
    return Fragment{it->first, it->second.first, it->second.second};
  }

  // Every intersection with [begin, end), clipped to the range, in address order.
  [[nodiscard]] std::vector<Fragment> intersections(std::uint64_t begin, std::uint64_t end) const {
    std::vector<Fragment> result;
    if (begin >= end) {
      return result;
    }
    for (auto it = range_start(begin); it != intervals_.end() && it->first < end; ++it) {
      const std::uint64_t clip_begin = it->first < begin ? begin : it->first;
      const std::uint64_t clip_end = it->second.first < end ? it->second.first : end;
      if (clip_begin < clip_end) {
        result.push_back(Fragment{clip_begin, clip_end, it->second.second});
      }
    }
    return result;
  }

  // Removes [begin, end) from the set: overlapping intervals are erased (full cover), shrunk
  // (prefix/suffix), or split (middle), across as many intervals as the range spans. Returns
  // the removed pieces, clipped to the range and carrying their values, in address order.
  std::vector<Fragment> subtract(std::uint64_t begin, std::uint64_t end) {
    std::vector<Fragment> removed;
    if (begin >= end) {
      return removed;
    }
    auto it = range_start(begin);
    while (it != intervals_.end() && it->first < end) {
      const std::uint64_t interval_begin = it->first;
      const std::uint64_t interval_end = it->second.first;
      const std::uint64_t clip_begin = interval_begin < begin ? begin : interval_begin;
      const std::uint64_t clip_end = interval_end < end ? interval_end : end;
      if (clip_begin < clip_end) {
        removed.push_back(Fragment{clip_begin, clip_end, it->second.second});
      }
      if (interval_begin < begin && interval_end > end) {
        // Middle split: shrink this interval to its prefix and spawn the suffix fragment.
        T value = it->second.second;
        it->second.first = begin;
        intervals_.emplace(end, std::pair{interval_end, std::move(value)});
        break;  // the suffix starts at end, so nothing later can intersect
      }
      if (interval_begin < begin) {
        // Suffix removal: keep the prefix.
        it->second.first = begin;
        ++it;
        continue;
      }
      if (interval_end > end) {
        // Prefix removal: the begin key changes, so erase and reinsert at end. No later
        // interval can start before end (the next one begins at or after interval_end).
        T value = std::move(it->second.second);
        it = intervals_.erase(it);
        intervals_.emplace(end, std::pair{interval_end, std::move(value)});
        continue;
      }
      it = intervals_.erase(it);  // fully covered
    }
    return removed;
  }

  // Inserts [begin, end) with value, evicting every existing overlap first; the evicted
  // pieces come back exactly like subtract returns them. Adjacent intervals are kept as
  // separate fragments (no coalescing — see the class contract).
  std::vector<Fragment> insert(std::uint64_t begin, std::uint64_t end, const T& value) {
    std::vector<Fragment> evicted = subtract(begin, end);
    if (begin < end) {
      intervals_.emplace(begin, std::pair{end, value});
    }
    return evicted;
  }

 private:
  using Entry = std::pair<std::uint64_t, T>;  // end, value

  // The interval that may contain point: the last one whose begin is not after point.
  typename std::map<std::uint64_t, Entry>::iterator candidate(std::uint64_t point) {
    auto it = intervals_.upper_bound(point);
    if (it == intervals_.begin()) {
      return intervals_.end();
    }
    --it;
    return it->second.first > point ? it : intervals_.end();
  }

  typename std::map<std::uint64_t, Entry>::const_iterator candidate(std::uint64_t point) const {
    auto it = intervals_.upper_bound(point);
    if (it == intervals_.begin()) {
      return intervals_.end();
    }
    --it;
    return it->second.first > point ? it : intervals_.end();
  }

  // The first interval that can intersect [begin, ...): the first one starting after begin,
  // backed up one step when the preceding interval reaches into the range.
  typename std::map<std::uint64_t, Entry>::iterator range_start(std::uint64_t begin) {
    auto it = intervals_.upper_bound(begin);
    if (it != intervals_.begin() && std::prev(it)->second.first > begin) {
      --it;
    }
    return it;
  }

  typename std::map<std::uint64_t, Entry>::const_iterator range_start(std::uint64_t begin) const {
    auto it = intervals_.upper_bound(begin);
    if (it != intervals_.begin() && std::prev(it)->second.first > begin) {
      --it;
    }
    return it;
  }

  std::map<std::uint64_t, Entry> intervals_;  // begin -> (end, value)
};

}  // namespace noleax::trace
