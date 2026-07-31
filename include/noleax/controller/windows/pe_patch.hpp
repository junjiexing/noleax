#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <stdexcept>
#include <string>

namespace noleax::controller::windows {

// Static PE patch (P7C): rewrites a copy of a native x64 executable so its
// entrypoint first runs an embedded bootstrap stub, then continues with the
// original entrypoint. The patch always produces a new output file; the input
// is never modified.

enum class PePatchError : std::uint8_t {
  kNone,
  kIo,               // file read/write/rename failure
  kTruncated,        // file ends inside a structure
  kNotPe,            // missing MZ/PE signature or malformed headers
  kNotX64,           // not an AMD64 PE32+ image
  kNotExecutable,    // DLL, driver or EFI image
  kManaged,          // CLR header present
  kPacked,           // packed-image heuristics
  kMalformed,        // sections or directories out of bounds
  kSigned,           // Authenticode signature present and not allowed
  kNoHeaderSpace,    // no room for one more section header
  kOverlay,          // unexpected data appended after the sections
  kOutputExists,     // output path already exists
};

class PePatchException final : public std::runtime_error {
 public:
  PePatchException(PePatchError code, const std::string& message);
  [[nodiscard]] PePatchError code() const noexcept;

 private:
  PePatchError code_;
};

struct PePatchOptions {
  std::filesystem::path input;
  std::filesystem::path output;
  std::string agent_name{"noleax-agent.dll"};
  bool allow_break_signature{false};
  bool verify{true};
};

struct PePatchResult {
  std::uint32_t entry_rva{0U};       // unchanged original entry point
  std::uint32_t section_rva{0U};     // bootstrap section VA
  std::uint32_t patch_rva{0U};       // where the entry jump was written
  std::uint64_t output_size{0U};
  bool signature_removed{false};
};

[[nodiscard]] PePatchResult patch_pe_image(const PePatchOptions& options);

// Describes an image patched by patch_pe_image, used by the run command to
// locate the embedded bootstrap parameters in the running process.
struct StaticPatchInfo {
  std::uint32_t entry_rva{0U};
  std::uint32_t section_rva{0U};
  std::uint32_t params_rva{0U};
};

[[nodiscard]] std::optional<StaticPatchInfo> read_static_patch_info(
    const std::filesystem::path& image);

}  // namespace noleax::controller::windows
