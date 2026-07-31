#include "noleax/controller/windows/diagnostics.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winternl.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <ios>
#include <ostream>
#include <string>
#include <string_view>
#include <utility>

namespace noleax::controller::windows {
namespace {

class Handle final {
 public:
  explicit Handle(HANDLE value = nullptr) noexcept : value_{value} {}
  ~Handle() {
    if (value_ != nullptr && value_ != INVALID_HANDLE_VALUE) {
      static_cast<void>(CloseHandle(value_));
    }
  }

  Handle(const Handle&) = delete;
  Handle& operator=(const Handle&) = delete;
  Handle(Handle&& other) noexcept : value_{std::exchange(other.value_, nullptr)} {}
  Handle& operator=(Handle&& other) noexcept {
    if (this != &other) {
      if (value_ != nullptr && value_ != INVALID_HANDLE_VALUE) {
        static_cast<void>(CloseHandle(value_));
      }
      value_ = std::exchange(other.value_, nullptr);
    }
    return *this;
  }

  [[nodiscard]] HANDLE get() const noexcept { return value_; }
  [[nodiscard]] bool valid() const noexcept {
    return value_ != nullptr && value_ != INVALID_HANDLE_VALUE;
  }

 private:
  HANDLE value_{nullptr};
};

[[nodiscard]] noleax::ipc::Architecture architecture_from_machine(USHORT machine) noexcept {
  switch (machine) {
    case IMAGE_FILE_MACHINE_I386:
      return noleax::ipc::Architecture::kX86;
    case IMAGE_FILE_MACHINE_AMD64:
      return noleax::ipc::Architecture::kX64;
    case IMAGE_FILE_MACHINE_ARM64:
      return noleax::ipc::Architecture::kArm64;
    default:
      return noleax::ipc::Architecture::kUnknown;
  }
}

[[nodiscard]] noleax::ipc::Architecture controller_architecture() noexcept {
#if defined(_M_X64) || defined(__x86_64__)
  return noleax::ipc::Architecture::kX64;
#elif defined(_M_IX86) || defined(__i386__)
  return noleax::ipc::Architecture::kX86;
#elif defined(_M_ARM64) || defined(__aarch64__)
  return noleax::ipc::Architecture::kArm64;
#else
  return noleax::ipc::Architecture::kUnknown;
#endif
}

[[nodiscard]] noleax::ipc::Architecture native_system_architecture() noexcept {
  SYSTEM_INFO information{};
  GetNativeSystemInfo(&information);
  switch (information.wProcessorArchitecture) {
    case PROCESSOR_ARCHITECTURE_INTEL:
      return noleax::ipc::Architecture::kX86;
    case PROCESSOR_ARCHITECTURE_AMD64:
      return noleax::ipc::Architecture::kX64;
    case PROCESSOR_ARCHITECTURE_ARM64:
      return noleax::ipc::Architecture::kArm64;
    default:
      return noleax::ipc::Architecture::kUnknown;
  }
}

template <typename Value>
[[nodiscard]] Value read_file_value(HANDLE file, std::uint64_t offset, const char* subject) {
  LARGE_INTEGER position{};
  position.QuadPart = static_cast<LONGLONG>(offset);
  if (SetFilePointerEx(file, position, nullptr, FILE_BEGIN) == FALSE) {
    const DWORD error = GetLastError();
    throw DiagnosticError{std::string{"cannot seek to "} + subject, error};
  }
  Value result{};
  DWORD bytes_read = 0U;
  if (ReadFile(file, &result, static_cast<DWORD>(sizeof(result)), &bytes_read, nullptr) == FALSE) {
    const DWORD error = GetLastError();
    throw DiagnosticError{std::string{"cannot read "} + subject, error};
  }
  if (bytes_read != sizeof(result)) {
    throw DiagnosticError{std::string{"truncated "} + subject, ERROR_BAD_EXE_FORMAT};
  }
  return result;
}

[[nodiscard]] std::string windows_version() {
  using RtlGetVersionFunction = NTSTATUS(WINAPI*)(PRTL_OSVERSIONINFOW);
  const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
  if (ntdll == nullptr) {
    return "unknown";
  }
  const auto procedure = reinterpret_cast<RtlGetVersionFunction>(
      GetProcAddress(ntdll, "RtlGetVersion"));  // NOLINT(performance-no-int-to-ptr)
  if (procedure == nullptr) {
    return "unknown";
  }
  RTL_OSVERSIONINFOW version{};
  version.dwOSVersionInfoSize = sizeof(version);
  if (procedure(&version) < 0) {
    return "unknown";
  }
  return std::to_string(version.dwMajorVersion) + "." + std::to_string(version.dwMinorVersion) +
         "." + std::to_string(version.dwBuildNumber);
}

[[nodiscard]] std::string elevation_state() {
  Handle token;
  HANDLE raw_token = nullptr;
  if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw_token) == FALSE) {
    return "unknown (Windows error " + std::to_string(GetLastError()) + ")";
  }
  token = Handle{raw_token};
  TOKEN_ELEVATION elevation{};
  DWORD returned = 0U;
  if (GetTokenInformation(token.get(), TokenElevation, &elevation, sizeof(elevation), &returned) ==
      FALSE) {
    return "unknown (Windows error " + std::to_string(GetLastError()) + ")";
  }
  return elevation.TokenIsElevated != 0U ? "elevated" : "not elevated";
}

[[nodiscard]] std::string mitigation_state() {
  PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY cfg{};
  const bool cfg_known =
      GetProcessMitigationPolicy(GetCurrentProcess(), ProcessControlFlowGuardPolicy, &cfg,
                                 sizeof(cfg)) != FALSE;
  PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY shadow_stack{};
  const bool shadow_known =
      GetProcessMitigationPolicy(GetCurrentProcess(), ProcessUserShadowStackPolicy, &shadow_stack,
                                 sizeof(shadow_stack)) != FALSE;
  const std::string cfg_value =
      cfg_known ? (cfg.EnableControlFlowGuard != 0U ? "on" : "off") : "unknown";
  const std::string cet_value =
      shadow_known ? (shadow_stack.EnableUserShadowStack != 0U ? "on" : "off") : "unknown";
  return "cfg=" + cfg_value + " cet-shadow-stack=" + cet_value;
}

[[nodiscard]] noleax::ipc::Architecture process_architecture(HANDLE process) {
  using IsWow64Process2Function = BOOL(WINAPI*)(HANDLE, USHORT*, USHORT*);
  const HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
  const auto procedure =
      kernel32 == nullptr
          ? nullptr
          : reinterpret_cast<IsWow64Process2Function>(GetProcAddress(kernel32, "IsWow64Process2"));
  if (procedure != nullptr) {
    USHORT process_machine = IMAGE_FILE_MACHINE_UNKNOWN;
    USHORT native_machine = IMAGE_FILE_MACHINE_UNKNOWN;
    if (procedure(process, &process_machine, &native_machine) == FALSE) {
      const DWORD error = GetLastError();
      throw DiagnosticError{"IsWow64Process2 failed", error};
    }
    return architecture_from_machine(
        process_machine == IMAGE_FILE_MACHINE_UNKNOWN ? native_machine : process_machine);
  }

  BOOL wow64 = FALSE;
  if (IsWow64Process(process, &wow64) == FALSE) {
    const DWORD error = GetLastError();
    throw DiagnosticError{"IsWow64Process failed", error};
  }
  if (wow64 != FALSE) {
    return noleax::ipc::Architecture::kX86;
  }
  return native_system_architecture();
}

void add(DoctorReport& report, DiagnosticSeverity severity, std::string name, std::string message,
         DiagnosticCategory category = DiagnosticCategory::kGeneral,
         std::uint32_t system_error = 0U) {
  report.entries.push_back(
      DiagnosticEntry{severity, category, std::move(name), std::move(message), system_error});
}

void diagnose_image(DoctorReport& report, const std::filesystem::path& path, bool agent) {
  const std::string name = agent ? "agent-image" : "target-image";
  try {
    PeImageInfo image = inspect_pe_image(path);
    if (image.architecture != noleax::ipc::Architecture::kX64) {
      add(report, DiagnosticSeverity::kError, name,
          std::string{architecture_name(image.architecture)} +
              " image is incompatible; P6 supports x64 only",
          DiagnosticCategory::kUnsupported);
      return;
    }
    if (agent && !image.is_dll) {
      add(report, DiagnosticSeverity::kError, name, "agent image is not a DLL");
      return;
    }
    if (!agent && image.is_dll) {
      add(report, DiagnosticSeverity::kError, name, "target image is a DLL, not an executable");
      return;
    }
    if (agent) {
      image = inspect_pe_image(path, true);
    }
    if (agent && !image.has_agent_bootstrap) {
      add(report, DiagnosticSeverity::kError, name,
          "agent DLL does not export noleax_agent_bootstrap");
      return;
    }
    add(report, DiagnosticSeverity::kOk, name,
        std::string{architecture_name(image.architecture)} +
            (image.pe32_plus ? " PE32+" : " PE32") + (image.is_dll ? " DLL" : " executable") +
            (agent ? ", bootstrap export present" : ""));
  } catch (const DiagnosticError& error) {
    add(report, DiagnosticSeverity::kError, name, error.what(), DiagnosticCategory::kGeneral,
        error.system_error());
  }
}

void diagnose_process(DoctorReport& report, std::uint32_t process_id) {
  if (process_id == 0U) {
    add(report, DiagnosticSeverity::kError, "target-process", "PID must be greater than zero");
    return;
  }
  Handle query{OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, process_id)};
  if (!query.valid()) {
    const DWORD error = GetLastError();
    add(report, DiagnosticSeverity::kError, "target-process",
        "cannot open PID " + std::to_string(process_id) + " for architecture query",
        error == ERROR_ACCESS_DENIED ? DiagnosticCategory::kPermission
                                     : DiagnosticCategory::kGeneral,
        error);
    return;
  }
  try {
    const auto architecture = process_architecture(query.get());
    if (architecture != noleax::ipc::Architecture::kX64) {
      add(report, DiagnosticSeverity::kError, "target-process",
          "PID " + std::to_string(process_id) + " is " +
              std::string{architecture_name(architecture)} + "; P6 supports x64 only",
          DiagnosticCategory::kUnsupported);
    } else {
      add(report, DiagnosticSeverity::kOk, "target-process",
          "PID " + std::to_string(process_id) + " is x64");
    }
  } catch (const DiagnosticError& error) {
    add(report, DiagnosticSeverity::kError, "target-process", error.what(),
        DiagnosticCategory::kGeneral, error.system_error());
  }

  constexpr DWORD required_access = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                                    PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_OPERATION |
                                    PROCESS_VM_READ | PROCESS_VM_WRITE | SYNCHRONIZE;
  Handle injection{OpenProcess(required_access, FALSE, process_id)};
  if (!injection.valid()) {
    const DWORD error = GetLastError();
    add(report, DiagnosticSeverity::kError, "open-process",
        "remote-thread access is unavailable for PID " + std::to_string(process_id),
        error == ERROR_ACCESS_DENIED ? DiagnosticCategory::kPermission
                                     : DiagnosticCategory::kGeneral,
        error);
  } else {
    add(report, DiagnosticSeverity::kOk, "open-process",
        "remote-thread access rights are available for PID " + std::to_string(process_id));
  }
}

[[nodiscard]] const char* severity_name(DiagnosticSeverity severity) noexcept {
  switch (severity) {
    case DiagnosticSeverity::kOk:
      return "ok";
    case DiagnosticSeverity::kWarning:
      return "warning";
    case DiagnosticSeverity::kError:
      return "error";
    case DiagnosticSeverity::kSkipped:
      return "skipped";
  }
  return "unknown";
}

}  // namespace

bool DoctorReport::has_errors() const noexcept {
  return std::ranges::any_of(entries, [](const DiagnosticEntry& entry) {
    return entry.severity == DiagnosticSeverity::kError;
  });
}

bool DoctorReport::has_error_category(DiagnosticCategory category) const noexcept {
  return std::ranges::any_of(entries, [category](const DiagnosticEntry& entry) {
    return entry.severity == DiagnosticSeverity::kError && entry.category == category;
  });
}

DiagnosticError::DiagnosticError(const std::string& message, std::uint32_t system_error)
    : std::runtime_error{message}, system_error_{system_error} {}

std::uint32_t DiagnosticError::system_error() const noexcept { return system_error_; }

std::string_view architecture_name(noleax::ipc::Architecture architecture) noexcept {
  switch (architecture) {
    case noleax::ipc::Architecture::kX86:
      return "x86";
    case noleax::ipc::Architecture::kX64:
      return "x64";
    case noleax::ipc::Architecture::kArm64:
      return "arm64";
    case noleax::ipc::Architecture::kUnknown:
      return "unknown";
  }
  return "unknown";
}

PeImageInfo inspect_pe_image(const std::filesystem::path& path, bool inspect_agent_bootstrap) {
  Handle file{CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr,
                          OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr)};
  if (!file.valid()) {
    const DWORD error = GetLastError();
    throw DiagnosticError{"cannot open PE image", error};
  }
  LARGE_INTEGER size{};
  if (GetFileSizeEx(file.get(), &size) == FALSE) {
    const DWORD error = GetLastError();
    throw DiagnosticError{"cannot query PE image size", error};
  }
  if (size.QuadPart < static_cast<LONGLONG>(sizeof(IMAGE_DOS_HEADER))) {
    throw DiagnosticError{"PE image is smaller than its DOS header", ERROR_BAD_EXE_FORMAT};
  }
  const IMAGE_DOS_HEADER dos = read_file_value<IMAGE_DOS_HEADER>(file.get(), 0U, "DOS header");
  if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < 0) {
    throw DiagnosticError{"invalid PE DOS header", ERROR_BAD_EXE_FORMAT};
  }
  const auto nt_offset = static_cast<std::uint64_t>(dos.e_lfanew);
  constexpr std::uint64_t minimum_nt_size =
      sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + sizeof(WORD);
  if (nt_offset > static_cast<std::uint64_t>(size.QuadPart) ||
      minimum_nt_size > static_cast<std::uint64_t>(size.QuadPart) - nt_offset) {
    throw DiagnosticError{"PE header lies outside the image", ERROR_BAD_EXE_FORMAT};
  }
  const DWORD signature = read_file_value<DWORD>(file.get(), nt_offset, "PE signature");
  if (signature != IMAGE_NT_SIGNATURE) {
    throw DiagnosticError{"invalid PE signature", ERROR_BAD_EXE_FORMAT};
  }
  const auto file_header_offset = nt_offset + sizeof(DWORD);
  const IMAGE_FILE_HEADER header =
      read_file_value<IMAGE_FILE_HEADER>(file.get(), file_header_offset, "PE file header");
  if (header.SizeOfOptionalHeader < sizeof(WORD)) {
    throw DiagnosticError{"PE optional header is missing", ERROR_BAD_EXE_FORMAT};
  }
  const auto optional_offset = file_header_offset + sizeof(header);
  if (optional_offset > static_cast<std::uint64_t>(size.QuadPart) ||
      header.SizeOfOptionalHeader > static_cast<std::uint64_t>(size.QuadPart) - optional_offset) {
    throw DiagnosticError{"truncated PE optional header", ERROR_BAD_EXE_FORMAT};
  }
  const WORD magic = read_file_value<WORD>(file.get(), optional_offset, "PE optional header");
  if (magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC && magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
    throw DiagnosticError{"unknown PE optional header format", ERROR_BAD_EXE_FORMAT};
  }
  const std::size_t minimum_optional_size = magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC
                                                ? sizeof(IMAGE_OPTIONAL_HEADER64)
                                                : sizeof(IMAGE_OPTIONAL_HEADER32);
  if (header.SizeOfOptionalHeader < minimum_optional_size || header.NumberOfSections == 0U) {
    throw DiagnosticError{"incomplete PE headers", ERROR_BAD_EXE_FORMAT};
  }

  PeImageInfo result;
  result.architecture = architecture_from_machine(header.Machine);
  if (result.architecture == noleax::ipc::Architecture::kUnknown) {
    throw DiagnosticError{"unsupported PE machine type", ERROR_BAD_EXE_FORMAT};
  }
  result.pe32_plus = magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
  result.is_dll = (header.Characteristics & IMAGE_FILE_DLL) != 0U;
  if ((result.architecture == noleax::ipc::Architecture::kX64 ||
       result.architecture == noleax::ipc::Architecture::kArm64) != result.pe32_plus) {
    throw DiagnosticError{"PE machine and optional header formats disagree", ERROR_BAD_EXE_FORMAT};
  }

  if (inspect_agent_bootstrap) {
    const HMODULE module = LoadLibraryExW(
        path.c_str(), nullptr, DONT_RESOLVE_DLL_REFERENCES | LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR);
    if (module == nullptr) {
      const DWORD error = GetLastError();
      throw DiagnosticError{"cannot map agent image without resolving imports", error};
    }
    result.has_agent_bootstrap = GetProcAddress(module, "noleax_agent_bootstrap") != nullptr;
    static_cast<void>(FreeLibrary(module));
  }
  return result;
}

DoctorReport run_doctor(const DoctorOptions& options) {
  DoctorReport report;
  const auto controller = controller_architecture();
  const auto operating_system = native_system_architecture();
  add(report,
      controller == noleax::ipc::Architecture::kX64 ? DiagnosticSeverity::kOk
                                                    : DiagnosticSeverity::kError,
      "controller", std::string{architecture_name(controller)},
      controller == noleax::ipc::Architecture::kX64 ? DiagnosticCategory::kGeneral
                                                    : DiagnosticCategory::kUnsupported);
  add(report,
      operating_system == noleax::ipc::Architecture::kX64 ? DiagnosticSeverity::kOk
                                                          : DiagnosticSeverity::kError,
      "operating-system",
      "Windows " + windows_version() + " " + std::string{architecture_name(operating_system)},
      operating_system == noleax::ipc::Architecture::kX64 ? DiagnosticCategory::kGeneral
                                                          : DiagnosticCategory::kUnsupported);
  add(report, DiagnosticSeverity::kOk, "hook-backend", "hoox 0.1.1");
  add(report, DiagnosticSeverity::kOk, "token", elevation_state());
  add(report, DiagnosticSeverity::kOk, "mitigations", mitigation_state());

  if (options.injection_method == "remote-thread" || options.injection_method == "thread-hijack" ||
      options.injection_method == "entrypoint-code" ||
      options.injection_method == "static-pe-patch") {
    add(report, DiagnosticSeverity::kOk, "injection-method",
        options.injection_method + " is supported on Windows x64");
  } else {
    add(report, DiagnosticSeverity::kError, "injection-method",
        options.injection_method + " is not implemented; run supports remote-thread, "
                                   "thread-hijack, entrypoint-code and static-pe-patch",
        DiagnosticCategory::kUnsupported);
  }

  if (options.agent_path.has_value()) {
    diagnose_image(report, *options.agent_path, true);
  } else {
    add(report, DiagnosticSeverity::kSkipped, "agent-image", "no agent path was provided");
  }
  if (options.target_path.has_value()) {
    diagnose_image(report, *options.target_path, false);
  } else {
    add(report, DiagnosticSeverity::kSkipped, "target-image", "no target path was provided");
  }
  if (options.process_id.has_value()) {
    diagnose_process(report, *options.process_id);
  } else {
    add(report, DiagnosticSeverity::kSkipped, "target-process", "no PID was provided");
    add(report, DiagnosticSeverity::kSkipped, "open-process", "no PID was provided");
  }
  return report;
}

void write_doctor_report(std::ostream& output, const DoctorReport& report) {
  std::array<std::uint64_t, 4U> counts{};
  output << "noleax doctor\n";
  for (const auto& entry : report.entries) {
    const auto index = static_cast<std::size_t>(entry.severity);
    if (index < counts.size()) {
      ++counts[index];
    }
    output << '[' << severity_name(entry.severity) << "] " << entry.name << ": " << entry.message;
    if (entry.system_error != 0U) {
      output << " (Windows error " << entry.system_error << ')';
    }
    output << '\n';
  }
  output << "summary: ok=" << counts[static_cast<std::size_t>(DiagnosticSeverity::kOk)]
         << " warning=" << counts[static_cast<std::size_t>(DiagnosticSeverity::kWarning)]
         << " error=" << counts[static_cast<std::size_t>(DiagnosticSeverity::kError)]
         << " skipped=" << counts[static_cast<std::size_t>(DiagnosticSeverity::kSkipped)] << '\n';
  if (!output) {
    throw DiagnosticError{"cannot write doctor output"};
  }
}

}  // namespace noleax::controller::windows
