#include "noleax/trace/module.hpp"

#include <algorithm>
#include <cstdint>
#include <limits>
#include <string_view>

namespace noleax::trace {
namespace {

void validate_string(std::string_view value, const char* field, bool required) {
  if (required && value.empty()) {
    throw ModuleValidationError{std::string{field} + " must not be empty"};
  }
  if (value.find('\0') != std::string_view::npos) {
    throw ModuleValidationError{std::string{field} + " must not contain NUL"};
  }
}

}  // namespace

void validate_module_load(const ModuleLoad& load) {
  if (!load.module_id) {
    throw ModuleValidationError{"module load requires a nonzero module_id"};
  }
  if (load.base_address == 0U || load.image_size == 0U ||
      load.image_size > std::numeric_limits<std::uint64_t>::max() - load.base_address) {
    throw ModuleValidationError{"module load address range is invalid"};
  }
  validate_string(load.image_path, "module image path", true);
  validate_string(load.pdb_path, "module PDB path", false);
  if ((load.flags & ~kKnownModuleLoadFlags) != 0U) {
    throw ModuleValidationError{"module load flags are not supported in V1"};
  }
  if (load.image_identity.has_value() && load.image_identity->image_size != load.image_size) {
    throw ModuleValidationError{"module PE identity size does not match the image range"};
  }
  if (!load.pdb_identity.has_value() && !load.pdb_path.empty()) {
    throw ModuleValidationError{"module PDB path requires a PDB identity"};
  }
}

void validate_module_unload(const ModuleUnload& unload) {
  if (!unload.module_id) {
    throw ModuleValidationError{"module unload requires a nonzero module_id"};
  }
}

}  // namespace noleax::trace
