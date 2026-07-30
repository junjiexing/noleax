#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <variant>

#include "noleax/trace/event.hpp"
#include "noleax/trace/identifiers.hpp"

namespace noleax::trace {

struct PeImageIdentity {
  std::uint32_t timestamp{0U};
  std::uint32_t checksum{0U};
  std::uint32_t image_size{0U};

  bool operator==(const PeImageIdentity&) const = default;
};

struct PdbIdentity {
  std::array<std::byte, 16> guid{};
  std::uint32_t age{0U};

  bool operator==(const PdbIdentity&) const = default;
};

enum class ModuleLoadFlag : std::uint32_t {  // NOLINT(performance-enum-size)
  kPathTruncated = 1U << 0U,
  kPdbPathTruncated = 1U << 1U,
};

inline constexpr std::uint32_t kKnownModuleLoadFlags =
    static_cast<std::uint32_t>(ModuleLoadFlag::kPathTruncated) |
    static_cast<std::uint32_t>(ModuleLoadFlag::kPdbPathTruncated);

struct ModuleLoad {
  ModuleId module_id;
  std::uint64_t monotonic_ticks{0U};
  Address base_address{0U};
  std::uint64_t image_size{0U};
  std::string image_path;
  std::optional<PeImageIdentity> image_identity;
  std::optional<PdbIdentity> pdb_identity;
  std::string pdb_path;
  std::uint32_t flags{0U};

  bool operator==(const ModuleLoad&) const = default;
};

struct ModuleUnload {
  ModuleId module_id;
  std::uint64_t monotonic_ticks{0U};

  bool operator==(const ModuleUnload&) const = default;
};

using ModuleRecord = std::variant<ModuleLoad, ModuleUnload>;

class ModuleValidationError final : public std::invalid_argument {
 public:
  using std::invalid_argument::invalid_argument;
};

void validate_module_load(const ModuleLoad& load);
void validate_module_unload(const ModuleUnload& unload);

}  // namespace noleax::trace
