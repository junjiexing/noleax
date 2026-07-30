#pragma once

#include <cstdint>
#include <filesystem>
#include <iosfwd>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include "noleax/ipc/protocol.hpp"

namespace noleax::controller::windows {

enum class DiagnosticSeverity : std::uint8_t {
  kOk,
  kWarning,
  kError,
  kSkipped,
};

enum class DiagnosticCategory : std::uint8_t {
  kGeneral,
  kUnsupported,
  kPermission,
};

struct DiagnosticEntry {
  DiagnosticSeverity severity{DiagnosticSeverity::kOk};
  DiagnosticCategory category{DiagnosticCategory::kGeneral};
  std::string name;
  std::string message;
  std::uint32_t system_error{0U};
};

struct PeImageInfo {
  noleax::ipc::Architecture architecture{noleax::ipc::Architecture::kUnknown};
  bool pe32_plus{false};
  bool is_dll{false};
  bool has_agent_bootstrap{false};
};

struct DoctorOptions {
  std::optional<std::filesystem::path> agent_path;
  std::optional<std::filesystem::path> target_path;
  std::optional<std::uint32_t> process_id;
  std::string injection_method{"remote-thread"};
};

struct DoctorReport {
  std::vector<DiagnosticEntry> entries;

  [[nodiscard]] bool has_errors() const noexcept;
  [[nodiscard]] bool has_error_category(DiagnosticCategory category) const noexcept;
};

class DiagnosticError final : public std::runtime_error {
 public:
  DiagnosticError(const std::string& message, std::uint32_t system_error = 0U);
  [[nodiscard]] std::uint32_t system_error() const noexcept;

 private:
  std::uint32_t system_error_{0U};
};

[[nodiscard]] std::string_view architecture_name(noleax::ipc::Architecture architecture) noexcept;
[[nodiscard]] PeImageInfo inspect_pe_image(const std::filesystem::path& path,
                                           bool inspect_agent_bootstrap = false);
[[nodiscard]] DoctorReport run_doctor(const DoctorOptions& options = {});
void write_doctor_report(std::ostream& output, const DoctorReport& report);

}  // namespace noleax::controller::windows
