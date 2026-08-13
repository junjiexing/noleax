// Ptrace attach injector (docs/LINUX_PORT_PLAN.md §M6). Seizes a running process with
// PTRACE_SEIZE, picks a safely-parked thread (never one inside ld.so, prefer one blocked
// in a syscall), maps an RWX stub page by single-stepping a `syscall; ret` gadget in the
// target's libc, and from there runs a tiny call stub for dlopen(agent) and a second one
// for noleax_agent_attach_bootstrap(parameters). All GP registers (including rflags) of
// every seized thread are saved at the interrupt stop and restored before detach, so an
// interrupted syscall continues per kernel rules.
//
// FP/vector state is deliberately not saved: the SysV AMD64 ABI makes every XMM/YMM/ZMM
// register call-clobbered, and the preferred injection point is a thread parked inside a
// libc syscall wrapper, i.e. exactly a call boundary across which no compiler keeps live
// vector state. Hijacking a thread that sits mid-vector-loop in user space (only reached
// through the fallback selection) inherits the same theoretical clobber risk that gdb's
// inferior calls have; documented as an accepted limitation, mirroring the Windows
// thread-hijack XSTATE note in docs/THREAD_HIJACK_INJECTION.md.

#include "noleax/controller/linux/ptrace_injector.hpp"

#if !defined(__x86_64__)
#error "PtraceInjector is implemented for x86-64 Linux only"
#endif

#include <dirent.h>
#include <dlfcn.h>
#include <elf.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <initializer_list>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#include "noleax/agent/linux/elf_symbol_lookup.hpp"
#include "noleax/agent/linux/hook_registry.hpp"
#include "noleax/controller/linux/controller.hpp"
#include "noleax/ipc/protocol.hpp"

namespace noleax::controller::linux {
namespace {

using Clock = std::chrono::steady_clock;

// Separate small budget for re-stopping a thread an error path left resumed.
constexpr std::chrono::milliseconds kReleaseStopTimeout{2'000};

constexpr std::uint64_t kStubPageSize = 0x1000U;
// Stub page layout: [code | path string | parameter blob].
constexpr std::uint64_t kStubCodeOffset = 0x0U;
constexpr std::uint64_t kStubPathOffset = 0x100U;
constexpr std::uint64_t kStubParamsOffset = 0x800U;
constexpr std::size_t kMaximumAgentPathBytes = 0x700U;
constexpr std::size_t kMaximumParameterBytes = kStubPageSize - kStubParamsOffset;

constexpr std::uint8_t kInt3Byte = 0xccU;
constexpr std::byte kInt3{kInt3Byte};
// `syscall; ret`: executed inside the target's libc mapping to invoke raw syscalls.
constexpr std::array<std::byte, 3U> kSyscallRetGadget{std::byte{0x0f}, std::byte{0x05},
                                                      std::byte{0xc3}};

[[nodiscard]] std::string hex_address(std::uint64_t value) {
  char buffer[24]{};
  std::snprintf(buffer, sizeof(buffer), "0x%llx", static_cast<unsigned long long>(value));
  return buffer;
}

[[noreturn]] void throw_errno(std::string_view what, int error) {
  const auto code = static_cast<std::uint32_t>(error);
  if (error == EPERM || error == EACCES) {
    throw ControllerError{
        std::string{what} +
            ": operation not permitted — ptrace attach needs a same-UID target with "
            "/proc/sys/kernel/yama/ptrace_scope <= 1, or CAP_SYS_PTRACE",
        code};
  }
  throw ControllerError{std::string{what} + ": " + std::strerror(error), code};
}

// ---------------------------------------------------------------------------
// minimal on-disk ELF64 view (dynsym lookup, executable segment bytes, PT_INTERP)
// ---------------------------------------------------------------------------

[[nodiscard]] std::vector<std::byte> read_whole_file(const std::filesystem::path& path) {
  std::ifstream input{path, std::ios::binary | std::ios::ate};
  if (!input) {
    throw_errno("cannot open '" + path.string() + "'", errno);
  }
  const std::streamoff size = input.tellg();
  if (size < 0) {
    throw ControllerError{"cannot size '" + path.string() + "'"};
  }
  std::vector<std::byte> bytes(static_cast<std::size_t>(size));
  input.seekg(0);
  if (size > 0 &&
      !input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(size))) {
    throw_errno("cannot read '" + path.string() + "'", errno);
  }
  return bytes;
}

class ElfFile final {
 public:
  explicit ElfFile(const std::filesystem::path& path) : bytes_{read_whole_file(path)} {
    parse(path);
  }

  ElfFile(const ElfFile&) = delete;
  ElfFile& operator=(const ElfFile&) = delete;
  ElfFile(ElfFile&&) = default;
  ElfFile& operator=(ElfFile&&) = default;

  [[nodiscard]] std::uint64_t minimum_load_vaddr() const noexcept { return minimum_load_vaddr_; }
  [[nodiscard]] const std::string& interpreter() const noexcept { return interpreter_; }

  // Link-time vaddr (st_value) of a defined .dynsym symbol.
  [[nodiscard]] std::optional<std::uint64_t> find_dynamic_symbol(std::string_view name) const {
    if (dynsym_.offset == 0U || strtab_.offset == 0U) {
      return std::nullopt;
    }
    const std::size_t count = dynsym_.size / sizeof(Elf64_Sym);
    for (std::size_t index = 0U; index < count; ++index) {
      Elf64_Sym symbol{};
      std::memcpy(&symbol, bytes_.data() + dynsym_.offset + index * sizeof(Elf64_Sym),
                  sizeof(symbol));
      if (symbol.st_shndx == SHN_UNDEF || symbol.st_name >= strtab_.size) {
        continue;
      }
      const char* const symbol_name =
          reinterpret_cast<const char*>(bytes_.data() + strtab_.offset + symbol.st_name);
      const std::size_t remaining = strtab_.size - symbol.st_name;
      if (name.size() + 1U > remaining) {
        continue;
      }
      if (std::string_view{symbol_name, name.size()} == name && symbol_name[name.size()] == '\0') {
        return symbol.st_value;
      }
    }
    return std::nullopt;
  }

  // Link-time vaddr of the first occurrence of `needle` in the executable PT_LOAD segment.
  [[nodiscard]] std::optional<std::uint64_t> find_executable_bytes(
      std::span<const std::byte> needle) const {
    if (!has_executable_segment_ || needle.empty() || needle.size() > executable_.size) {
      return std::nullopt;
    }
    const std::byte* const begin = bytes_.data() + executable_.offset;
    const std::byte* const end = begin + (executable_.size - needle.size());
    for (const std::byte* cursor = begin; cursor <= end; ++cursor) {
      if (std::memcmp(cursor, needle.data(), needle.size()) == 0) {
        return executable_.vaddr + static_cast<std::uint64_t>(cursor - begin);
      }
    }
    return std::nullopt;
  }

 private:
  struct FileRange {
    std::uint64_t offset{0};
    std::uint64_t size{0};
    std::uint64_t vaddr{0};
  };

  [[nodiscard]] bool contains(std::uint64_t offset, std::uint64_t size) const noexcept {
    return offset <= bytes_.size() && size <= bytes_.size() - offset;
  }

  void parse(const std::filesystem::path& path) {
    const std::string what = "'" + path.string() + "' is not a readable x86-64 ELF image";
    if (!contains(0U, sizeof(Elf64_Ehdr))) {
      throw ControllerError{what};
    }
    Elf64_Ehdr header{};
    std::memcpy(&header, bytes_.data(), sizeof(header));
    if (std::memcmp(header.e_ident, ELFMAG, SELFMAG) != 0 ||
        header.e_ident[EI_CLASS] != ELFCLASS64 || header.e_ident[EI_DATA] != ELFDATA2LSB ||
        header.e_machine != EM_X86_64 || header.e_phentsize < sizeof(Elf64_Phdr)) {
      throw ControllerError{what};
    }
    if (!contains(header.e_phoff,
                  static_cast<std::uint64_t>(header.e_phnum) * header.e_phentsize)) {
      throw ControllerError{what};
    }
    bool have_load = false;
    for (std::uint16_t index = 0U; index < header.e_phnum; ++index) {
      Elf64_Phdr program{};
      const std::uint64_t at =
          header.e_phoff + static_cast<std::uint64_t>(index) * header.e_phentsize;
      std::memcpy(&program, bytes_.data() + at, sizeof(program));
      if (program.p_type == PT_LOAD) {
        if (!have_load || program.p_vaddr < minimum_load_vaddr_) {
          minimum_load_vaddr_ = program.p_vaddr;
          have_load = true;
        }
        if ((program.p_flags & PF_X) != 0U && !has_executable_segment_ &&
            contains(program.p_offset, program.p_filesz)) {
          executable_ = FileRange{program.p_offset, program.p_filesz, program.p_vaddr};
          has_executable_segment_ = true;
        }
      } else if (program.p_type == PT_INTERP && contains(program.p_offset, program.p_filesz)) {
        const char* const begin = reinterpret_cast<const char*>(bytes_.data() + program.p_offset);
        interpreter_.assign(begin, ::strnlen(begin, program.p_filesz));
      }
    }
    if (!have_load || header.e_shoff == 0U || header.e_shentsize < sizeof(Elf64_Shdr) ||
        !contains(header.e_shoff,
                  static_cast<std::uint64_t>(header.e_shnum) * header.e_shentsize)) {
      return;  // sections are optional for our purposes (interpreter-only images)
    }
    const auto section_at = [&](std::uint16_t index) {
      return header.e_shoff + static_cast<std::uint64_t>(index) * header.e_shentsize;
    };
    for (std::uint16_t index = 0U; index < header.e_shnum; ++index) {
      Elf64_Shdr section{};
      std::memcpy(&section, bytes_.data() + section_at(index), sizeof(section));
      if (section.sh_type != SHT_DYNSYM || section.sh_link >= header.e_shnum ||
          !contains(section.sh_offset, section.sh_size)) {
        continue;
      }
      Elf64_Shdr strings{};
      std::memcpy(&strings, bytes_.data() + section_at(static_cast<std::uint16_t>(section.sh_link)),
                  sizeof(strings));
      if (!contains(strings.sh_offset, strings.sh_size)) {
        continue;
      }
      dynsym_ = FileRange{section.sh_offset, section.sh_size, 0U};
      strtab_ = FileRange{strings.sh_offset, strings.sh_size, 0U};
      return;
    }
  }

  std::vector<std::byte> bytes_;
  std::uint64_t minimum_load_vaddr_{0};
  std::string interpreter_;
  FileRange executable_{};
  bool has_executable_segment_{false};
  FileRange dynsym_{};
  FileRange strtab_{};
};

// ---------------------------------------------------------------------------
// /proc views
// ---------------------------------------------------------------------------

struct ProcessMapping {
  std::uint64_t start{0};
  std::uint64_t end{0};
  std::uint64_t file_offset{0};
  std::string path;
};

[[nodiscard]] std::string_view base_name(std::string_view path) {
  const std::size_t slash = path.rfind('/');
  return slash == std::string_view::npos ? path : path.substr(slash + 1U);
}

[[nodiscard]] std::vector<ProcessMapping> read_mappings(pid_t pid) {
  const std::string maps_path = "/proc/" + std::to_string(pid) + "/maps";
  std::ifstream input{maps_path};
  if (!input) {
    throw_errno("cannot read " + maps_path, errno);
  }
  std::vector<ProcessMapping> mappings;
  std::string line;
  while (std::getline(input, line)) {
    unsigned long long start = 0U;
    unsigned long long end = 0U;
    unsigned long long offset = 0U;
    int consumed = 0;
    if (std::sscanf(line.c_str(), "%llx-%llx %*4s %llx %*s %*u%n", &start, &end, &offset,
                    &consumed) != 3) {
      continue;  // not a mapping line: skip rather than fail the attach
    }
    ProcessMapping mapping;
    mapping.start = static_cast<std::uint64_t>(start);
    mapping.end = static_cast<std::uint64_t>(end);
    mapping.file_offset = static_cast<std::uint64_t>(offset);
    std::string_view rest{line};
    rest = rest.substr(static_cast<std::size_t>(consumed));
    const std::size_t first = rest.find_first_not_of(' ');
    if (first != std::string_view::npos) {
      mapping.path = std::string{rest.substr(first)};
    }
    mappings.push_back(std::move(mapping));
  }
  return mappings;
}

// One mapped module resolved against its on-disk image: the maps entry with file offset 0
// anchors the load bias, and the on-disk ELF provides vaddrs and gadget bytes.
struct TargetModule {
  std::string path;
  ElfFile image;
  std::uint64_t bias{0};
};

[[nodiscard]] std::optional<TargetModule> open_mapped_module(
    const std::vector<ProcessMapping>& mappings, std::initializer_list<std::string_view> prefixes) {
  for (const std::string_view prefix : prefixes) {
    for (const ProcessMapping& mapping : mappings) {
      if (mapping.file_offset != 0U || mapping.path.empty() ||
          !base_name(mapping.path).starts_with(prefix)) {
        continue;
      }
      ElfFile image{mapping.path};
      return TargetModule{mapping.path, std::move(image),
                          mapping.start - image.minimum_load_vaddr()};
    }
  }
  return std::nullopt;
}

// Load bias of the module whose maps path resolves to `canonical_path` (the caller's
// agent path after symlink resolution).
[[nodiscard]] std::optional<std::uint64_t> module_bias_for_path(
    const std::vector<ProcessMapping>& mappings, const std::filesystem::path& canonical_path,
    std::uint64_t minimum_load_vaddr) {
  const std::string wanted = canonical_path.string();
  for (const ProcessMapping& mapping : mappings) {
    if (mapping.file_offset != 0U || mapping.path.empty()) {
      continue;
    }
    if (mapping.path == wanted) {
      return mapping.start - minimum_load_vaddr;
    }
    std::error_code error;
    if (std::filesystem::weakly_canonical(mapping.path, error) == canonical_path && !error) {
      return mapping.start - minimum_load_vaddr;
    }
  }
  return std::nullopt;
}

[[nodiscard]] std::vector<pid_t> list_threads(pid_t pid) {
  const std::string task_dir = "/proc/" + std::to_string(pid) + "/task";
  DIR* const dir = ::opendir(task_dir.c_str());
  if (dir == nullptr) {
    const int error = errno;
    if (error == ENOENT) {
      throw ControllerError{"process " + std::to_string(pid) + " does not exist",
                            static_cast<std::uint32_t>(error)};
    }
    throw_errno("cannot enumerate the threads of process " + std::to_string(pid), error);
  }
  std::vector<pid_t> tids;
  while (const dirent* const entry = ::readdir(dir)) {
    const std::string_view name{entry->d_name};
    if (name.empty() ||
        !std::all_of(name.begin(), name.end(), [](char c) { return c >= '0' && c <= '9'; })) {
      continue;
    }
    tids.push_back(static_cast<pid_t>(std::strtol(entry->d_name, nullptr, 10)));
  }
  ::closedir(dir);
  if (tids.empty()) {
    throw ControllerError{"process " + std::to_string(pid) + " has no threads (already exited?)"};
  }
  return tids;
}

// True when /proc/<pid>/task/<tid>/syscall reports the thread parked inside a syscall
// (a syscall number, not "running"). Unreadable states count as not-in-syscall.
[[nodiscard]] bool thread_blocked_in_syscall(pid_t pid, pid_t tid) {
  std::ifstream input{"/proc/" + std::to_string(pid) + "/task/" + std::to_string(tid) + "/syscall"};
  std::string first;
  if (!(input >> first) || first == "running") {
    return false;
  }
  char* end = nullptr;
  const long number = std::strtol(first.c_str(), &end, 10);
  return end != first.c_str() && number >= 0;
}

// ---------------------------------------------------------------------------
// ptrace primitives
// ---------------------------------------------------------------------------

[[nodiscard]] void* remote_pointer(std::uint64_t address) {
  return reinterpret_cast<void*>(static_cast<std::uintptr_t>(address));
}

[[nodiscard]] std::uint64_t peek_word(pid_t tid, std::uint64_t address) {
  errno = 0;
  const long value = ::ptrace(PTRACE_PEEKDATA, tid, remote_pointer(address), nullptr);
  if (value == -1L && errno != 0) {
    throw_errno(
        "PTRACE_PEEKDATA failed at " + hex_address(address) + " of thread " + std::to_string(tid),
        errno);
  }
  return static_cast<std::uint64_t>(value);
}

void poke_word(pid_t tid, std::uint64_t address, std::uint64_t value) {
  if (::ptrace(PTRACE_POKEDATA, tid, remote_pointer(address), remote_pointer(value)) != 0) {
    throw_errno(
        "PTRACE_POKEDATA failed at " + hex_address(address) + " of thread " + std::to_string(tid),
        errno);
  }
}

void write_memory(pid_t tid, std::uint64_t address, std::span<const std::byte> bytes) {
  std::uint64_t cursor = address;
  std::size_t written = 0U;
  while (written < bytes.size()) {
    const std::uint64_t word_address = cursor & ~std::uint64_t{7U};
    const auto in_word = static_cast<std::size_t>(cursor - word_address);
    const std::size_t chunk = std::min(sizeof(std::uint64_t) - in_word, bytes.size() - written);
    std::uint64_t word = 0U;
    if (in_word != 0U || chunk != sizeof(std::uint64_t)) {
      word = peek_word(tid, word_address);  // preserve the bytes outside the written range
    }
    std::memcpy(reinterpret_cast<std::byte*>(&word) + in_word, bytes.data() + written, chunk);
    poke_word(tid, word_address, word);
    cursor += chunk;
    written += chunk;
  }
}

[[nodiscard]] user_regs_struct get_registers(pid_t tid) {
  user_regs_struct regs{};
  if (::ptrace(PTRACE_GETREGS, tid, nullptr, &regs) != 0) {
    throw_errno("PTRACE_GETREGS failed for thread " + std::to_string(tid), errno);
  }
  return regs;
}

void set_registers(pid_t tid, const user_regs_struct& regs) {
  if (::ptrace(PTRACE_SETREGS, tid, nullptr, &regs) != 0) {
    throw_errno("PTRACE_SETREGS failed for thread " + std::to_string(tid), errno);
  }
}

struct ThreadStop {
  enum class Kind : std::uint8_t { kStopped, kExited, kSignaled, kGone, kTimedOut };
  Kind kind{Kind::kGone};
  int signal{0};
};

// Reports kTimedOut instead of throwing when the deadline passes, so the stub runner can
// grant the in-flight call its grace budget before declaring the stub wedged.
[[nodiscard]] ThreadStop wait_for_thread(pid_t tid, Clock::time_point deadline) {
  for (;;) {
    int status = 0;
    const pid_t result = ::waitpid(tid, &status, WNOHANG | __WALL);
    if (result == tid) {
      if (WIFEXITED(status)) {
        return ThreadStop{ThreadStop::Kind::kExited, WEXITSTATUS(status)};
      }
      if (WIFSIGNALED(status)) {
        return ThreadStop{ThreadStop::Kind::kSignaled, WTERMSIG(status)};
      }
      if (WIFSTOPPED(status)) {
        return ThreadStop{ThreadStop::Kind::kStopped, WSTOPSIG(status)};
      }
    } else if (result < 0) {
      if (errno == EINTR) {
        continue;
      }
      if (errno == ECHILD) {
        return ThreadStop{ThreadStop::Kind::kGone, 0};
      }
      throw_errno("waitpid failed for thread " + std::to_string(tid), errno);
    }
    if (Clock::now() >= deadline) {
      return ThreadStop{ThreadStop::Kind::kTimedOut, 0};
    }
    std::this_thread::sleep_for(std::chrono::milliseconds{1});
  }
}

// ---------------------------------------------------------------------------
// the seized thread set (RAII: restore + detach on every path)
// ---------------------------------------------------------------------------

struct SeizedThread {
  pid_t tid{0};
  user_regs_struct saved_regs{};
  bool stopped{false};     // currently inside a ptrace stop
  bool running{false};     // currently resumed by us (CONT/SINGLESTEP)
  bool regs_valid{false};  // saved_regs holds the pre-injection register state
  int pending_signal{0};   // real signal observed at a stop; redelivered on detach
};

class Seizure final {
 public:
  Seizure(pid_t pid, Clock::time_point deadline) {
    try {
      seize_all(pid, deadline);
    } catch (...) {
      release_all();
      throw;
    }
  }

  ~Seizure() { release_all(); }

  Seizure(const Seizure&) = delete;
  Seizure& operator=(const Seizure&) = delete;

  [[nodiscard]] std::vector<SeizedThread>& threads() noexcept { return threads_; }

  // Wedged-stub path (H1-B): a thread is still inside the injected call after the
  // injection budget plus the grace budget. Restoring its pre-hijack registers would
  // teleport it out of mid-agent code (memory corruption), so abandon the whole seizure
  // instead: best-effort re-stop the wedged thread, then leave every thread seized and
  // stopped — nothing is restored, nothing is detached, the process stays frozen.
  void abandon(SeizedThread& wedged) noexcept {
    if (wedged.running) {
      if (::ptrace(PTRACE_INTERRUPT, wedged.tid, nullptr, nullptr) == 0) {
        try {
          wedged.stopped = wait_for_thread(wedged.tid, Clock::now() + kReleaseStopTimeout).kind ==
                           ThreadStop::Kind::kStopped;
        } catch (...) {
          wedged.stopped = false;
        }
      }
      wedged.running = false;
    }
    abandon_ = true;
  }

 private:
  void seize_all(pid_t pid, Clock::time_point deadline) {
    // The thread set may change during the walk: re-enumerate until a full pass finds
    // no new tid. Threads that vanish mid-walk fail with ESRCH and are skipped.
    for (;;) {
      bool found_new = false;
      for (const pid_t tid : list_threads(pid)) {
        const bool known = std::any_of(threads_.begin(), threads_.end(),
                                       [tid](const SeizedThread& t) { return t.tid == tid; });
        if (known) {
          continue;
        }
        if (::ptrace(PTRACE_SEIZE, tid, nullptr, nullptr) != 0) {
          const int error = errno;
          if (error == ESRCH) {
            continue;
          }
          throw_errno(
              "cannot seize thread " + std::to_string(tid) + " of process " + std::to_string(pid),
              error);
        }
        threads_.push_back(SeizedThread{.tid = tid});
        found_new = true;
      }
      if (!found_new) {
        break;
      }
      if (Clock::now() >= deadline) {
        throw ControllerError{"the thread set of process " + std::to_string(pid) +
                              " keeps changing; cannot seize a stable set"};
      }
    }
    for (SeizedThread& thread : threads_) {
      if (::ptrace(PTRACE_INTERRUPT, thread.tid, nullptr, nullptr) != 0 && errno != ESRCH) {
        throw_errno("cannot interrupt thread " + std::to_string(thread.tid), errno);
      }
    }
    for (SeizedThread& thread : threads_) {
      const ThreadStop stop = wait_for_thread(thread.tid, deadline);
      if (stop.kind == ThreadStop::Kind::kTimedOut) {
        throw ControllerError{"timed out waiting for thread " + std::to_string(thread.tid) +
                              " to stop (injection budget exhausted)"};
      }
      if (stop.kind != ThreadStop::Kind::kStopped) {
        continue;  // exited between seize and wait: nothing to restore or inject into
      }
      thread.stopped = true;
      if (stop.signal != SIGTRAP) {
        // A real signal raced the interrupt stop; redeliver it when we detach.
        thread.pending_signal = stop.signal;
      }
      thread.saved_regs = get_registers(thread.tid);
      thread.regs_valid = true;
    }
  }

  void release_all() noexcept {
    if (abandon_) {
      // Wedged stub: leave the whole process seized and stopped. The attach must be
      // retried against a restarted target; detaching here would either resume a thread
      // inside mid-agent code or strand the rest with no diagnosis.
      threads_.clear();
      return;
    }
    for (SeizedThread& thread : threads_) {
      if (thread.running) {
        // An error path left the thread resumed: re-stop it before touching registers
        // or detaching (both require a stopped tracee).
        if (::ptrace(PTRACE_INTERRUPT, thread.tid, nullptr, nullptr) == 0) {
          try {
            thread.stopped = wait_for_thread(thread.tid, Clock::now() + kReleaseStopTimeout).kind ==
                             ThreadStop::Kind::kStopped;
          } catch (...) {
            thread.stopped = false;
          }
        }
        thread.running = false;
      }
      if (thread.stopped && thread.regs_valid) {
        static_cast<void>(::ptrace(PTRACE_SETREGS, thread.tid, nullptr, &thread.saved_regs));
      }
      static_cast<void>(
          ::ptrace(PTRACE_DETACH, thread.tid, nullptr,
                   remote_pointer(static_cast<std::uint64_t>(thread.pending_signal))));
    }
    threads_.clear();
  }

  std::vector<SeizedThread> threads_;
  bool abandon_{false};
};

// Resumes the thread and waits for our SIGTRAP (the stub's int3 or the single-step
// trap). Unrelated asynchronous signals are kept pending for detach and the wait
// continues; a synchronous fault means the stub itself went wrong and fails fast;
// the thread dying mid-stub or the deadline expiring is an injection failure.
//
// Deadline handling (H1-B): an expiry while the thread is still inside the stub is NOT
// proof of a wedge — the injected call is finite (bounded connect + bounded install) and
// may legitimately outlive the main budget on a loaded machine. The thread therefore gets
// one additional grace budget (grace_deadline) to reach the int3. Only a stub that
// outlives the grace is wedged: the seizure is abandoned (no register restore, no
// detach, process left stopped) and the failure is raised as a loud, distinct error —
// restoring the pre-hijack registers here would teleport a thread out of mid-agent code.
[[nodiscard]] user_regs_struct run_to_trap(Seizure& seizure, pid_t tid, SeizedThread& thread,
                                           Clock::time_point deadline,
                                           Clock::time_point grace_deadline, bool single_step) {
  for (;;) {
    if (::ptrace(single_step ? PTRACE_SINGLESTEP : PTRACE_CONT, tid, nullptr, nullptr) != 0) {
      throw_errno("cannot resume thread " + std::to_string(tid), errno);
    }
    thread.running = true;
    thread.stopped = false;
    ThreadStop stop = wait_for_thread(tid, deadline);
    if (stop.kind == ThreadStop::Kind::kTimedOut && Clock::now() < grace_deadline) {
      stop = wait_for_thread(tid, grace_deadline);
    }
    if (stop.kind == ThreadStop::Kind::kTimedOut) {
      seizure.abandon(thread);
      throw ControllerError{
          "the injected call on thread " + std::to_string(tid) +
          " did not reach its completion trap within the injection timeout plus one grace "
          "budget; the thread is wedged inside the agent bootstrap. The target process is "
          "INCONSISTENT: it was left stopped under ptrace with no registers restored and "
          "no threads detached, and it must be restarted before the controller exits"};
    }
    thread.running = false;
    thread.stopped = stop.kind == ThreadStop::Kind::kStopped;
    if (stop.kind != ThreadStop::Kind::kStopped) {
      throw ControllerError{"the injection thread " + std::to_string(tid) +
                            " terminated while running the injection stub"};
    }
    if (stop.signal == SIGSEGV || stop.signal == SIGILL || stop.signal == SIGBUS ||
        stop.signal == SIGFPE) {
      // Continuing a faulting instruction would re-fault forever: fail now, with the
      // faulting address for diagnosis. The signal is ours, not the target's, so it is
      // swallowed rather than redelivered on detach.
      siginfo_t info{};
      static_cast<void>(::ptrace(PTRACE_GETSIGINFO, tid, nullptr, &info));
      const user_regs_struct faulted = get_registers(tid);
      throw ControllerError{"the injection stub faulted with signal " +
                            std::to_string(stop.signal) + " at rip=" + hex_address(faulted.rip) +
                            " touching " +
                            hex_address(reinterpret_cast<std::uintptr_t>(info.si_addr))};
    }
    if (stop.signal != SIGTRAP) {
      if (thread.pending_signal == 0) {
        thread.pending_signal = stop.signal;
      }
      continue;
    }
    return get_registers(tid);
  }
}

// Prepares the register set for running the stub at `entry`: starts from the saved state,
// then clears the pending syscall-restart bookkeeping. A thread parked in a syscall holds
// rax=-ERESTART_* with orig_rax=<nr>, and resuming it with those values makes the kernel
// restart the syscall by rewinding rip by 2 (the size of the syscall instruction) — the
// stub would enter at entry-2 and run wild. orig_rax=-1 marks "not in a syscall" and rax
// gets a plain non-ERESTART value; the saved pair is restored before detach, so the
// interrupted syscall still restarts at the original rip per kernel rules.
[[nodiscard]] user_regs_struct redirect_registers(const user_regs_struct& saved,
                                                  std::uint64_t entry) {
  user_regs_struct regs = saved;
  regs.rax = 0U;
  regs.orig_rax = ~std::uint64_t{0U};
  regs.rip = entry;
  return regs;
}

// ---------------------------------------------------------------------------
// injection stub
// ---------------------------------------------------------------------------

constexpr std::size_t kCallStubSize = 37U;

// Position-independent call stub poked at kStubCodeOffset:
//   and    rsp, -16          48 83 e4 f0
//   movabs rdi, arg1         48 bf <imm64>
//   movabs rsi, arg2         48 be <imm64>
//   movabs rax, function     48 b8 <imm64>
//   call   rax               ff d0
//   int3                     cc
// The alignment fix keeps SSE spills (movaps) inside dlopen fault-free no matter what rsp
// the hijacked thread was parked with; every register the stub or the callee clobbers is
// restored from the saved user_regs_struct afterwards. The return value is read from rax
// at the int3 stop.
[[nodiscard]] std::array<std::byte, kCallStubSize> make_call_stub(std::uint64_t function,
                                                                  std::uint64_t arg1,
                                                                  std::uint64_t arg2) {
  std::array<std::byte, kCallStubSize> stub{};
  std::size_t at = 0U;
  const auto emit = [&at, &stub](std::initializer_list<std::uint8_t> bytes) {
    for (const std::uint8_t byte : bytes) {
      stub[at++] = static_cast<std::byte>(byte);
    }
  };
  const auto emit_imm64 = [&at, &stub](std::uint64_t value) {
    for (unsigned shift = 0U; shift < 64U; shift += 8U) {
      stub[at++] = static_cast<std::byte>((value >> shift) & 0xffU);
    }
  };
  emit({0x48U, 0x83U, 0xe4U, 0xf0U});  // and rsp, -16
  emit({0x48U, 0xbfU});                // movabs rdi, arg1
  emit_imm64(arg1);
  emit({0x48U, 0xbeU});  // movabs rsi, arg2
  emit_imm64(arg2);
  emit({0x48U, 0xb8U});  // movabs rax, function
  emit_imm64(function);
  emit({0xffU, 0xd0U});  // call rax
  emit({kInt3Byte});     // int3
  return stub;
}

// ---------------------------------------------------------------------------
// patch-window evacuation (H1-B)
// ---------------------------------------------------------------------------

// A fast-hook transaction overwrites the whole instructions covering the redirect
// sequence (a 5-byte near jump plus at most one straddling instruction — never more than
// ~20 bytes on x86-64); 32 covers every hoox overwrite with margin. The window starts at
// symbol+1: a thread parked exactly at the entry resumes into the new redirect, which is
// safe in both patch directions (mirrors hoox's own guard-interval convention).
constexpr std::uint64_t kPatchWindowSize = 32U;
// Bound on the single-step evacuation per thread: a thread that has not left the window
// by then is looping inside it, and the attach must fail (pre-patch, so restore+detach
// stays safe) instead of corrupting it.
constexpr unsigned kMaxEvacuationSteps = 64U;

using PatchWindow = std::pair<std::uint64_t, std::uint64_t>;  // half-open [begin, end)

// With hoox's external thread suspension set, its in-process park AND the park-driven
// PC-in-prologue guard scan are both skipped — that is the point of the stop window. The
// price: this injector must guarantee that no ptrace-stopped thread sits with its rip
// inside a to-be-overwritten prologue, or the resume after detach would decode the middle
// of the redirect bytes (observed in the field as a SIGILL minutes into the capture).
// The sweep below single-steps every such thread out of the window BEFORE any stub runs
// a patch; the steps execute the thread's own instructions, so the stepped state becomes
// its new saved state and the detach-time restore lands safely outside the window.
[[nodiscard]] bool inside_patch_window(std::uint64_t rip,
                                       const std::vector<PatchWindow>& windows) noexcept {
  return std::any_of(windows.begin(), windows.end(), [rip](const PatchWindow& window) {
    return rip >= window.first && rip < window.second;
  });
}

void add_patch_window(std::vector<PatchWindow>& windows, std::uint64_t function_address) {
  windows.emplace_back(function_address + 1U, function_address + 1U + kPatchWindowSize);
}

// Best-effort runtime address of one custom-hook role: the agent resolves the same
// declaration at install time; the injector mirrors it so the evacuation sweep also
// covers custom targets (a churning third-party allocator is exactly the hot case).
void add_custom_hook_windows(const noleax::ipc::CustomHookSpec& spec,
                             const std::vector<ProcessMapping>& mappings,
                             std::vector<PatchWindow>& windows) {
  const ProcessMapping* module_mapping = nullptr;
  for (const ProcessMapping& mapping : mappings) {
    if (mapping.file_offset != 0U || mapping.path.empty()) {
      continue;
    }
    if (mapping.path == spec.module || base_name(mapping.path) == spec.module) {
      module_mapping = &mapping;
      break;
    }
  }
  if (module_mapping == nullptr) {
    return;  // not loaded (yet): the agent's own resolution degrades the point
  }
  std::optional<ElfFile> image;
  std::optional<std::uint64_t> bias;
  const auto resolve = [&](const noleax::ipc::CustomHookRoleSpec& role) {
    if (role.locator == noleax::ipc::CustomHookLocator::kRva) {
      windows.emplace_back(module_mapping->start + role.rva + 1U,
                           module_mapping->start + role.rva + 1U + kPatchWindowSize);
      return;
    }
    if (role.locator != noleax::ipc::CustomHookLocator::kExport &&
        role.locator != noleax::ipc::CustomHookLocator::kElfSymbol) {
      return;
    }
    if (!image.has_value()) {
      image.emplace(module_mapping->path);
      bias = module_mapping->start - image->minimum_load_vaddr();
    }
    std::optional<std::uint64_t> vaddr =
        role.locator == noleax::ipc::CustomHookLocator::kExport
            ? image->find_dynamic_symbol(role.export_name)
            : noleax::agent::linux::find_elf_symbol_vaddr(module_mapping->path, role.export_name);
    if (vaddr.has_value()) {
      add_patch_window(windows, *bias + *vaddr);
    }
  };
  resolve(spec.alloc);
  resolve(spec.realloc);
  resolve(spec.free);
}

// Single-steps one seized thread until its rip leaves every patch window. Runs before any
// patch is written, so every failure here is an ordinary pre-stub failure (restore +
// detach is still safe). The stepped state is adopted into saved_regs after every stop,
// so the detach-time restore never rewinds real target progress into a patched window.
void evacuate_thread_from_patch_windows(SeizedThread& thread,
                                        const std::vector<PatchWindow>& windows,
                                        Clock::time_point deadline) {
  for (unsigned steps = 0U;;) {
    const user_regs_struct current = get_registers(thread.tid);
    if (!inside_patch_window(current.rip, windows)) {
      thread.saved_regs = current;
      return;
    }
    if (steps == kMaxEvacuationSteps) {
      throw ControllerError{"thread " + std::to_string(thread.tid) +
                            " of the attach target does not leave the patch window at rip=" +
                            hex_address(current.rip) +
                            "; the attach was aborted before any patch was written"};
    }
    ++steps;
    if (::ptrace(PTRACE_SINGLESTEP, thread.tid, nullptr, nullptr) != 0) {
      if (errno == ESRCH) {
        thread.regs_valid = false;  // died mid-evacuation: nothing to restore for it
        return;
      }
      throw_errno("cannot single-step thread " + std::to_string(thread.tid), errno);
    }
    thread.running = true;
    thread.stopped = false;
    const ThreadStop stop = wait_for_thread(thread.tid, deadline);
    if (stop.kind == ThreadStop::Kind::kTimedOut) {
      // Keep running=true so the error path re-stops the thread before restoring. Only a
      // stuck (uninterruptible) instruction gets here, and the adopted state rewinds at
      // most the one in-flight instruction.
      thread.running = true;
      throw ControllerError{"timed out single-stepping thread " + std::to_string(thread.tid) +
                            " out of a patch window (injection budget exhausted)"};
    }
    thread.running = false;
    thread.stopped = stop.kind == ThreadStop::Kind::kStopped;
    if (stop.kind != ThreadStop::Kind::kStopped) {
      thread.regs_valid = false;  // exited or died mid-step: never restore over it
      return;
    }
    if (stop.signal != SIGTRAP) {
      // A real signal interrupted the step; keep it pending for detach. The instruction
      // may not have executed — the loop re-reads the rip and decides again.
      if (thread.pending_signal == 0) {
        thread.pending_signal = stop.signal;
      }
    }
  }
}

// Reject threads parked inside ld.so (possible loader-lock holders); prefer a thread
// blocked in a syscall. Better to refuse than to inject into a risky thread.
[[nodiscard]] SeizedThread& select_injection_thread(
    std::vector<SeizedThread>& threads, pid_t pid,
    const std::vector<std::pair<std::uint64_t, std::uint64_t>>& linker_ranges) {
  SeizedThread* fallback = nullptr;
  for (SeizedThread& thread : threads) {
    if (!thread.stopped || !thread.regs_valid) {
      continue;
    }
    const std::uint64_t rip = thread.saved_regs.rip;
    const bool in_linker =
        std::any_of(linker_ranges.begin(), linker_ranges.end(),
                    [rip](const auto& range) { return rip >= range.first && rip < range.second; });
    if (in_linker) {
      continue;
    }
    if (fallback == nullptr) {
      fallback = &thread;
    }
    if (thread_blocked_in_syscall(pid, thread.tid)) {
      return thread;
    }
  }
  if (fallback != nullptr) {
    return *fallback;
  }
  throw ControllerError{"no thread is safe to inject into: every thread of process " +
                        std::to_string(pid) + " is parked inside the dynamic linker"};
}

}  // namespace

void PtraceInjector::inject(std::uint32_t process_id, const std::filesystem::path& agent_path,
                            const std::vector<std::byte>& bootstrap_parameters,
                            std::chrono::milliseconds timeout,
                            const std::vector<noleax::ipc::CustomHookSpec>& custom_hooks) {
  if (process_id == 0U) {
    throw ControllerError{"process id must not be zero", EINVAL};
  }
  const auto pid = static_cast<pid_t>(process_id);
  if (pid == ::getpid()) {
    throw ControllerError{"cannot inject into the controller process itself", EINVAL};
  }
  if (agent_path.empty()) {
    throw ControllerError{"agent path must not be empty", EINVAL};
  }
  if (bootstrap_parameters.empty() || bootstrap_parameters.size() > kMaximumParameterBytes) {
    throw ControllerError{
        "the bootstrap parameter blob is empty or larger than the stub "
        "page area",
        EINVAL};
  }
  if (timeout <= std::chrono::milliseconds::zero()) {
    throw ControllerError{"injection timeout must be positive", EINVAL};
  }

  // Everything that can fail before touching the target fails here (same rule as the
  // Windows injectors: no half-prepared state ever reaches the threads).
  std::error_code canonical_error;
  const std::filesystem::path canonical_agent =
      std::filesystem::canonical(agent_path, canonical_error);
  if (canonical_error) {
    throw ControllerError{"agent image '" + agent_path.string() + "' does not exist", ENOENT};
  }
  const std::string agent_file = canonical_agent.string();
  if (agent_file.size() + 1U > kMaximumAgentPathBytes) {
    throw ControllerError{"agent path is too long for the stub page", ENAMETOOLONG};
  }
  const ElfFile agent_image{canonical_agent};
  const auto bootstrap_vaddr = agent_image.find_dynamic_symbol("noleax_agent_attach_bootstrap");
  if (!bootstrap_vaddr.has_value()) {
    throw ControllerError{"agent image '" + agent_file +
                          "' does not export noleax_agent_attach_bootstrap"};
  }

  // One configured budget covers the whole sequence (seizure → dlopen → bootstrap →
  // handshake → install). A deadline expiry mid-stub is not yet a wedge: the in-flight
  // call is finite, so it gets one extra timeout-sized grace budget to reach its int3.
  const Clock::time_point deadline = Clock::now() + timeout;
  const Clock::time_point grace_deadline = deadline + timeout;
  Seizure seizure{pid, deadline};
  const std::vector<ProcessMapping> mappings = read_mappings(pid);

  // The dynamic linker's mapping, for the thread-selection rejection rule. The target
  // executable's PT_INTERP names it; the ld-*/ld.* basename is the fallback heuristic.
  std::vector<std::pair<std::uint64_t, std::uint64_t>> linker_ranges;
  std::string linker_path;
  try {
    linker_path = ElfFile{"/proc/" + std::to_string(pid) + "/exe"}.interpreter();
  } catch (const ControllerError&) {
    // Unreadable or unusual executable: the name heuristic below still applies.
  }
  for (const ProcessMapping& mapping : mappings) {
    if (mapping.path.empty()) {
      continue;
    }
    const std::string_view name = base_name(mapping.path);
    const bool by_name = name.starts_with("ld-") || name.starts_with("ld.");
    if (by_name || (!linker_path.empty() && mapping.path == linker_path)) {
      linker_ranges.emplace_back(mapping.start, mapping.end);
    }
  }

  // libc carries dlopen (glibc >= 2.34), the syscall;ret gadget, and the int3 byte.
  // Older glibc keeps dlopen in libdl; both images come from the target's own mappings.
  auto libc = open_mapped_module(mappings, {"libc.so", "libc-", "libc.musl"});
  if (!libc.has_value()) {
    throw ControllerError{
        "the target process has no libc mapping; attach to statically "
        "linked targets is not supported"};
  }
  auto dlopen_vaddr = libc->image.find_dynamic_symbol("dlopen");
  std::uint64_t dlopen_bias = libc->bias;
  if (!dlopen_vaddr.has_value()) {
    auto libdl = open_mapped_module(mappings, {"libdl.so", "libdl-"});
    if (libdl.has_value()) {
      dlopen_vaddr = libdl->image.find_dynamic_symbol("dlopen");
      dlopen_bias = libdl->bias;
    }
  }
  if (!dlopen_vaddr.has_value()) {
    throw ControllerError{"cannot locate dlopen in the target's C library"};
  }
  const auto gadget_vaddr = libc->image.find_executable_bytes(kSyscallRetGadget);
  if (!gadget_vaddr.has_value()) {
    throw ControllerError{"no syscall;ret gadget found in the target's libc"};
  }
  const auto int3_vaddr = libc->image.find_executable_bytes(std::span<const std::byte>{&kInt3, 1U});
  if (!int3_vaddr.has_value()) {
    throw ControllerError{"no int3 byte found in the target's libc"};
  }

  // Evacuate every seized thread that is stopped inside a patch window BEFORE the first
  // stub runs: the bootstrap installs its hooks under hoox's external thread suspension,
  // which disables the in-process park AND its PC-in-prologue guard scan, so this sweep
  // is the only thing standing between a stopped thread and a resume into the middle of
  // an overwritten prologue. The window set covers every function the agent can patch
  // inside the stop window: the built-in registry symbols resolved from the target's
  // libc, the exit/_exit self-finalize hooks, and the declared custom hook targets.
  std::vector<PatchWindow> patch_windows;
  for (const noleax::agent::linux::LinuxHookRegistryEntry& entry :
       noleax::agent::linux::kLinuxHookRegistry) {
    for (const std::string_view name : entry.exports()) {
      if (const auto vaddr = libc->image.find_dynamic_symbol(name); vaddr.has_value()) {
        add_patch_window(patch_windows, libc->bias + *vaddr);
      }
    }
  }
  for (const std::string_view name : {std::string_view{"exit"}, std::string_view{"_exit"}}) {
    if (const auto vaddr = libc->image.find_dynamic_symbol(name); vaddr.has_value()) {
      add_patch_window(patch_windows, libc->bias + *vaddr);
    }
  }
  for (const noleax::ipc::CustomHookSpec& spec : custom_hooks) {
    add_custom_hook_windows(spec, mappings, patch_windows);
  }
  for (SeizedThread& thread : seizure.threads()) {
    if (!thread.stopped || !thread.regs_valid) {
      continue;
    }
    evacuate_thread_from_patch_windows(thread, patch_windows, deadline);
  }

  SeizedThread& hijack = select_injection_thread(seizure.threads(), pid, linker_ranges);
  const pid_t tid = hijack.tid;
  const std::uint64_t gadget_address = libc->bias + *gadget_vaddr;
  const std::uint64_t int3_address = libc->bias + *int3_vaddr;
  const std::uint64_t dlopen_address = dlopen_bias + *dlopen_vaddr;

  // Stage 0: map the stub page by single-stepping the libc `syscall; ret` gadget with
  // mmap arguments in registers. A fake return frame below the parked rsp points at the
  // int3 byte, so if the kernel's step semantics let the `ret` run (or the CONT fallback
  // below engages), control still lands on a trap instead of running wild.
  user_regs_struct regs = redirect_registers(hijack.saved_regs, gadget_address);
  const std::uint64_t frame_rsp = (regs.rsp - 16U) & ~std::uint64_t{15U};
  poke_word(tid, frame_rsp, int3_address);
  regs.rax = static_cast<std::uint64_t>(SYS_mmap);
  regs.rdi = 0U;
  regs.rsi = kStubPageSize;
  regs.rdx = static_cast<std::uint64_t>(PROT_READ | PROT_WRITE | PROT_EXEC);
  regs.r10 = static_cast<std::uint64_t>(MAP_PRIVATE | MAP_ANONYMOUS);
  regs.r8 = ~std::uint64_t{0U};  // fd -1
  regs.r9 = 0U;
  regs.rsp = frame_rsp;
  set_registers(tid, regs);
  regs = run_to_trap(seizure, tid, hijack, deadline, grace_deadline, /*single_step=*/true);
  if (regs.rax == static_cast<std::uint64_t>(SYS_mmap)) {
    // Stopped before the syscall executed: run on; the fake frame catches the ret.
    regs = run_to_trap(seizure, tid, hijack, deadline, grace_deadline, /*single_step=*/false);
  }
  const auto mmap_result = static_cast<std::int64_t>(regs.rax);
  if (mmap_result < 0 && mmap_result >= -4095L) {
    throw_errno("the target's mmap of the stub page failed", static_cast<int>(-mmap_result));
  }
  if ((regs.rax & 0xfffU) != 0U) {
    throw ControllerError{"the target's mmap syscall did not produce a page"};
  }
  const std::uint64_t stub_page = regs.rax;

  // Stage 1: dlopen(agent_path, RTLD_NOW | RTLD_LOCAL). The path string and the
  // parameter blob live inside the stub page.
  std::vector<std::byte> path_bytes(agent_file.size() + 1U);
  std::memcpy(path_bytes.data(), agent_file.c_str(), agent_file.size() + 1U);
  write_memory(tid, stub_page + kStubPathOffset, path_bytes);
  write_memory(tid, stub_page + kStubParamsOffset, bootstrap_parameters);
  write_memory(tid, stub_page + kStubCodeOffset,
               make_call_stub(dlopen_address, stub_page + kStubPathOffset,
                              static_cast<std::uint64_t>(RTLD_NOW | RTLD_LOCAL)));
  regs = redirect_registers(hijack.saved_regs, stub_page + kStubCodeOffset);
  set_registers(tid, regs);
  regs = run_to_trap(seizure, tid, hijack, deadline, grace_deadline, /*single_step=*/false);
  if (regs.rax == 0U) {
    throw ControllerError{"dlopen('" + agent_file + "') failed inside the target process"};
  }

  // Stage 2: locate the freshly mapped agent and call the attach bootstrap export.
  const auto agent_bias =
      module_bias_for_path(read_mappings(pid), canonical_agent, agent_image.minimum_load_vaddr());
  if (!agent_bias.has_value()) {
    throw ControllerError{"dlopen succeeded but '" + agent_file +
                          "' is not visible in the target's mappings"};
  }
  write_memory(tid, stub_page + kStubCodeOffset,
               make_call_stub(*agent_bias + *bootstrap_vaddr, stub_page + kStubParamsOffset, 0U));
  regs = redirect_registers(hijack.saved_regs, stub_page + kStubCodeOffset);
  set_registers(tid, regs);
  regs = run_to_trap(seizure, tid, hijack, deadline, grace_deadline, /*single_step=*/false);
  const auto bootstrap_result = static_cast<std::uint32_t>(regs.rax);
  if (bootstrap_result != 0U) {
    throw ControllerError{"noleax_agent_attach_bootstrap returned " +
                          std::to_string(bootstrap_result)};
  }
  // The synchronous attach bootstrap returned only after installing every hook inside
  // the stop window, so no business thread can meet a half-written prologue on resume.
  // Seizure's destructor restores every thread's saved registers and detaches.
}

}  // namespace noleax::controller::linux
