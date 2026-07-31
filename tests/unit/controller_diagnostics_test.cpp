#include "noleax/controller/windows/diagnostics.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <atomic>
#include <catch2/catch_test_macros.hpp>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>

namespace {

class TemporaryFile final {
 public:
  TemporaryFile() {
    static std::atomic<std::uint64_t> sequence{0U};
    path_ = std::filesystem::temp_directory_path() /
            ("noleax-diagnostics-" +
             std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + "-" +
             std::to_string(sequence.fetch_add(1U)) + ".bin");
  }

  ~TemporaryFile() {
    std::error_code error;
    static_cast<void>(std::filesystem::remove(path_, error));
  }

  TemporaryFile(const TemporaryFile&) = delete;
  TemporaryFile& operator=(const TemporaryFile&) = delete;

  [[nodiscard]] const std::filesystem::path& path() const noexcept { return path_; }

 private:
  std::filesystem::path path_;
};

}  // namespace

TEST_CASE("Windows diagnostics inspect the shipped x64 images", "[controller][doctor][windows]") {
  const auto agent = noleax::controller::windows::inspect_pe_image(NOLEAX_TEST_AGENT_PATH, true);
  CHECK(agent.architecture == noleax::ipc::Architecture::kX64);
  CHECK(agent.pe32_plus);
  CHECK(agent.is_dll);
  CHECK(agent.has_agent_bootstrap);

  const auto target =
      noleax::controller::windows::inspect_pe_image(NOLEAX_TEST_CONTROLLER_TARGET_PATH);
  CHECK(target.architecture == noleax::ipc::Architecture::kX64);
  CHECK(target.pe32_plus);
  CHECK_FALSE(target.is_dll);
}

TEST_CASE("Windows diagnostics reject malformed PE input with a stable error",
          "[controller][doctor][windows]") {
  TemporaryFile file;
  {
    std::ofstream output{file.path(), std::ios::binary | std::ios::trunc};
    REQUIRE(output);
    output << "not a portable executable";
  }

  try {
    static_cast<void>(noleax::controller::windows::inspect_pe_image(file.path()));
    FAIL("malformed input should fail");
  } catch (const noleax::controller::windows::DiagnosticError& error) {
    CHECK(std::string{error.what()} == "PE image is smaller than its DOS header");
    CHECK(error.system_error() == ERROR_BAD_EXE_FORMAT);
  }
}

TEST_CASE("Windows doctor is read-only and diagnoses current-process access",
          "[controller][doctor][windows]") {
  noleax::controller::windows::DoctorOptions options;
  options.agent_path = std::filesystem::path{NOLEAX_TEST_AGENT_PATH};
  options.target_path = std::filesystem::path{NOLEAX_TEST_CONTROLLER_TARGET_PATH};
  options.process_id = GetCurrentProcessId();

  const auto report = noleax::controller::windows::run_doctor(options);
  CHECK_FALSE(report.has_errors());

  std::ostringstream output;
  noleax::controller::windows::write_doctor_report(output, report);
  CHECK(output.str().find("[ok] injection-method: remote-thread is supported on Windows x64") !=
        std::string::npos);
  CHECK(output.str().find("[ok] open-process: remote-thread access rights are available") !=
        std::string::npos);
  CHECK(output.str().find("summary: ok=") != std::string::npos);

  options.injection_method = "thread-hijack";
  const auto hijack = noleax::controller::windows::run_doctor(options);
  CHECK_FALSE(hijack.has_errors());

  options.injection_method = "entrypoint-code";
  const auto unsupported = noleax::controller::windows::run_doctor(options);
  CHECK(unsupported.has_error_category(
      noleax::controller::windows::DiagnosticCategory::kUnsupported));
}
