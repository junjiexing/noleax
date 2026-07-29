#pragma once

#include <compare>
#include <cstdint>
#include <type_traits>

namespace noleax::trace {

template <typename Tag, typename Representation>
class Identifier {
  static_assert(std::is_unsigned_v<Representation>);

 public:
  using representation_type = Representation;

  constexpr Identifier() noexcept = default;
  explicit constexpr Identifier(Representation value) noexcept : value_{value} {}

  [[nodiscard]] constexpr Representation value() const noexcept { return value_; }
  [[nodiscard]] constexpr bool is_valid() const noexcept { return value_ != 0; }
  [[nodiscard]] explicit constexpr operator bool() const noexcept { return is_valid(); }

  auto operator<=>(const Identifier&) const = default;

 private:
  Representation value_{0};
};

struct SequenceTag;
struct ModuleIdTag;
struct StackIdTag;
struct AllocationIdTag;
struct HeapIdTag;
struct MappingIdTag;

using Sequence = Identifier<SequenceTag, std::uint64_t>;
using ModuleId = Identifier<ModuleIdTag, std::uint64_t>;
using StackId = Identifier<StackIdTag, std::uint64_t>;
using AllocationId = Identifier<AllocationIdTag, std::uint64_t>;
using HeapId = Identifier<HeapIdTag, std::uint64_t>;
using MappingId = Identifier<MappingIdTag, std::uint64_t>;
using ApiId = std::uint32_t;

static_assert(sizeof(Sequence) == sizeof(std::uint64_t));
static_assert(sizeof(ApiId) == sizeof(std::uint32_t));

}  // namespace noleax::trace
