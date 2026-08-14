#include "noleax/controller/linux/diagnostics.hpp"

#include <dlfcn.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <ostream>
#include <string>
#include <string_view>

namespace noleax::controller::linux {
namespace {

[[nodiscard]] std::uint16_t read_u16_le(const unsigned char* bytes) noexcept {
  return static_cast<std::uint16_t>(bytes[0]) |
         static_cast<std::uint16_t>(static_cast<std::uint16_t>(bytes[1]) << 8U);
}

[[nodiscard]] std::uint32_t read_u32_le(const unsigned char* bytes) noexcept {
  std::uint32_t value = 0U;
  for (std::size_t index = 0U; index < sizeof(value); ++index) {
    value |= static_cast<std::uint32_t>(bytes[index]) << (index * 8U);
  }
  return value;
}

[[nodiscard]] std::uint64_t read_u64_le(const unsigned char* bytes) noexcept {
  std::uint64_t value = 0U;
  for (std::size_t index = 0U; index < sizeof(value); ++index) {
    value |= static_cast<std::uint64_t>(bytes[index]) << (index * 8U);
  }
  return value;
}

using Entry = DiagnosticEntry;

Entry make_entry(DiagnosticSeverity severity, std::string name, std::string message,
                 DiagnosticCategory category = DiagnosticCategory::kGeneral,
                 std::uint32_t system_error = 0U) {
  return DiagnosticEntry{severity, category, std::move(name), std::move(message), system_error};
}

[[nodiscard]] std::string_view severity_name(DiagnosticSeverity severity) noexcept {
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

struct ElfIdentity {
  bool is_elf{false};
  bool is_64bit{false};
  bool is_x86_64{false};
  bool is_shared{false};   // ET_DYN
  bool is_dynamic{false};  // has PT_INTERP or ET_DYN
  std::string error;
};

// Minimal ELF64 header inspection: identity, architecture, and whether the image is
// dynamically linked (a static target cannot be preloaded).
[[nodiscard]] ElfIdentity inspect_elf(const std::filesystem::path& path) {
  ElfIdentity identity;
  const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    identity.error = std::strerror(errno);
    return identity;
  }

  std::array<unsigned char, 64> header{};
  const ssize_t count = ::pread(fd, header.data(), header.size(), 0);
  ::close(fd);
  if (count < static_cast<ssize_t>(header.size())) {
    identity.error = "short read on the ELF header";
    return identity;
  }
  if (std::memcmp(header.data(), "\177ELF", 4U) != 0) {
    identity.error = "not an ELF image";
    return identity;
  }
  identity.is_elf = true;
  identity.is_64bit = header[4] == 2U;                           // EI_CLASS
  identity.is_x86_64 = header[18] == 0x3eU && header[19] == 0U;  // e_machine
  const std::uint16_t type = read_u16_le(header.data() + 16U);
  identity.is_shared = type == 3U;  // ET_DYN
  if (!identity.is_shared) {
    // ET_EXEC: dynamic only when a PT_INTERP program header exists.
    const std::uint64_t phoff = read_u64_le(header.data() + 32U);
    const std::uint16_t phentsize = read_u16_le(header.data() + 54U);
    const std::uint16_t phnum = read_u16_le(header.data() + 56U);
    const int fd_headers = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd_headers >= 0) {
      for (std::uint32_t index = 0U; index < phnum && phentsize >= 56U; ++index) {
        std::array<unsigned char, 56> program{};
        if (::pread(fd_headers, program.data(), program.size(),
                    static_cast<off_t>(phoff + index * phentsize)) !=
            static_cast<ssize_t>(program.size())) {
          break;
        }
        if (read_u32_le(program.data()) == 3U) {  // PT_INTERP
          identity.is_dynamic = true;
          break;
        }
      }
      ::close(fd_headers);
    }
  } else {
    identity.is_dynamic = true;
  }
  return identity;
}

void check_platform(DoctorReport& report) {
  utsname system{};
  if (::uname(&system) != 0) {
    report.entries.push_back(make_entry(DiagnosticSeverity::kError, "platform", "uname failed", {},
                                        static_cast<std::uint32_t>(errno)));
    return;
  }
  const bool x86_64 = std::string_view{system.machine} == "x86_64";
  report.entries.push_back(
      make_entry(x86_64 ? DiagnosticSeverity::kOk : DiagnosticSeverity::kError, "platform",
                 std::string{system.sysname} + " " + system.machine +
                     (x86_64 ? "" : " (only Linux x86-64 is supported)"),
                 x86_64 ? DiagnosticCategory::kGeneral : DiagnosticCategory::kUnsupported));
}

void check_agent(DoctorReport& report, const std::filesystem::path& agent_path) {
  std::error_code error;
  if (!std::filesystem::exists(agent_path, error)) {
    report.entries.push_back(
        make_entry(DiagnosticSeverity::kError, "agent", "agent image not found"));
    return;
  }
  const ElfIdentity identity = inspect_elf(agent_path);
  if (!identity.is_elf || !identity.is_64bit || !identity.is_x86_64 || !identity.is_shared) {
    report.entries.push_back(
        make_entry(DiagnosticSeverity::kError, "agent",
                   "agent image is not a 64-bit x86-64 shared object: " + identity.error,
                   DiagnosticCategory::kUnsupported));
    return;
  }

  // Probe the agent in-process: the constructor stays inert without the bootstrap
  // environment, and the linkage check exercises the hoox backend end to end.
  void* const module = ::dlopen(agent_path.c_str(), RTLD_NOW | RTLD_LOCAL);
  if (module == nullptr) {
    const char* const load_error = ::dlerror();
    report.entries.push_back(make_entry(
        DiagnosticSeverity::kError, "agent",
        std::string{"cannot load the agent: "} + (load_error != nullptr ? load_error : "unknown"),
        {}, 0U));
    return;
  }
  const auto verify =
      reinterpret_cast<bool (*)()>(::dlsym(module, "noleax_agent_verify_hook_backend_linkage"));
  const auto abi_version =
      reinterpret_cast<std::uint32_t (*)()>(::dlsym(module, "noleax_agent_abi_version"));
  bool linkage_ok = false;
  std::uint32_t abi = 0U;
  if (verify != nullptr) {
    linkage_ok = verify();
  }
  if (abi_version != nullptr) {
    abi = abi_version();
  }
  ::dlclose(module);

  report.entries.push_back(
      make_entry(linkage_ok ? DiagnosticSeverity::kOk : DiagnosticSeverity::kError, "agent",
                 "agent loads; hook backend linkage " + std::string{linkage_ok ? "ok" : "FAILED"} +
                     ", abi " + std::to_string(abi)));
}

void check_target(DoctorReport& report, const std::filesystem::path& target_path) {
  std::error_code error;
  if (!std::filesystem::exists(target_path, error)) {
    report.entries.push_back(
        make_entry(DiagnosticSeverity::kError, "target", "target image not found"));
    return;
  }
  const ElfIdentity identity = inspect_elf(target_path);
  if (!identity.is_elf || !identity.is_64bit || !identity.is_x86_64) {
    report.entries.push_back(make_entry(DiagnosticSeverity::kError, "target",
                                        "target is not a 64-bit x86-64 ELF image",
                                        DiagnosticCategory::kUnsupported));
    return;
  }
  if (!identity.is_dynamic) {
    report.entries.push_back(
        make_entry(DiagnosticSeverity::kError, "target",
                   "static target: LD_PRELOAD injection is impossible (no dynamic loader)",
                   DiagnosticCategory::kUnsupported));
    return;
  }

  struct stat status {};
  if (::stat(target_path.c_str(), &status) != 0) {
    report.entries.push_back(make_entry(DiagnosticSeverity::kWarning, "target",
                                        "cannot stat the target", {},
                                        static_cast<std::uint32_t>(errno)));
    return;
  }
  if ((status.st_mode & (S_ISUID | S_ISGID)) != 0U) {
    report.entries.push_back(
        make_entry(DiagnosticSeverity::kWarning, "target",
                   "setuid/setgid target: the loader ignores LD_PRELOAD under AT_SECURE",
                   DiagnosticCategory::kPermission));
    return;
  }
  report.entries.push_back(make_entry(DiagnosticSeverity::kOk, "target",
                                      "dynamic x86-64 ELF, injectable via ld-preload"));
}

void check_ptrace_scope(DoctorReport& report) {
  const int fd = ::open("/proc/sys/kernel/yama/ptrace_scope", O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    report.entries.push_back(
        make_entry(DiagnosticSeverity::kOk, "ptrace-scope",
                   "Yama ptrace_scope not present (no ptrace restriction detected)"));
    return;
  }
  char buffer[8]{};
  const ssize_t count = ::read(fd, buffer, sizeof(buffer) - 1U);
  ::close(fd);
  if (count <= 0) {
    report.entries.push_back(make_entry(DiagnosticSeverity::kWarning, "ptrace-scope",
                                        "cannot read ptrace_scope", {},
                                        static_cast<std::uint32_t>(errno)));
    return;
  }
  const int scope = buffer[0] - '0';
  const bool attach_ready = scope <= 1;
  report.entries.push_back(make_entry(
      attach_ready ? DiagnosticSeverity::kOk : DiagnosticSeverity::kWarning, "ptrace-scope",
      "ptrace_scope=" + std::to_string(scope) +
          (attach_ready ? " (parent/child attach allowed)"
                        : " (attach requires CAP_SYS_PTRACE or relaxation; attach lands in M6)"),
      attach_ready ? DiagnosticCategory::kGeneral : DiagnosticCategory::kPermission));
}

void check_symbolization(DoctorReport& report) {
  // The ELF/DWARF-lite backend is compiled into the analyzer (no external dependency).
  report.entries.push_back(make_entry(DiagnosticSeverity::kOk, "symbolization",
                                      "built-in ELF symbol backend available"));
}

}  // namespace

DiagnosticError::DiagnosticError(const std::string& message, std::uint32_t system_error)
    : std::runtime_error{message}, system_error_{system_error} {}

std::uint32_t DiagnosticError::system_error() const noexcept { return system_error_; }

bool DoctorReport::has_errors() const noexcept {
  for (const auto& entry : entries) {
    if (entry.severity == DiagnosticSeverity::kError) {
      return true;
    }
  }
  return false;
}

bool DoctorReport::has_error_category(DiagnosticCategory category) const noexcept {
  for (const auto& entry : entries) {
    if (entry.severity == DiagnosticSeverity::kError && entry.category == category) {
      return true;
    }
  }
  return false;
}

DoctorReport run_doctor(const DoctorOptions& options) {
  DoctorReport report;
  check_platform(report);
  if (options.agent_path.has_value()) {
    check_agent(report, *options.agent_path);
  } else {
    report.entries.push_back(
        make_entry(DiagnosticSeverity::kSkipped, "agent", "no agent probe supplied"));
  }
  if (options.target_path.has_value()) {
    check_target(report, *options.target_path);
  } else {
    report.entries.push_back(
        make_entry(DiagnosticSeverity::kSkipped, "target", "no target probe supplied"));
  }
  check_ptrace_scope(report);
  check_symbolization(report);
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
      output << " (errno " << entry.system_error << ')';
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

}  // namespace noleax::controller::linux
