#include "noleax/controller/windows/thread_hijack_injector.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <memory>
#include <string>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#include "injection_common.hpp"

namespace noleax::controller::windows {
namespace {

using injection::fail;
using injection::find_remote_module_resilient;
using injection::Handle;
using injection::local_procedure_offset;
using injection::remote_ntdll_procedure;
using injection::RemoteMemory;
using injection::try_unload_remote_module;

// x64 bootstrap stub executed by the hijacked thread. Assembled with ml64 from
// the reference source recorded in docs/THREAD_HIJACK_INJECTION.md; the byte
// sequence below is verified against that disassembly.
//
// Entry contract: rcx = HijackStubData. The stub may clobber every register
// because the controller restores the full saved CONTEXT afterwards; it never
// returns and parks in a final spin loop until the controller restores RIP.
constexpr std::array<std::byte, 164U> kHijackStub{
    std::byte{0x4C}, std::byte{0x8B}, std::byte{0xE1},                   // mov r12,rcx
    std::byte{0x4C}, std::byte{0x8B}, std::byte{0xEC},                   // mov r13,rsp
    std::byte{0x48}, std::byte{0x83}, std::byte{0xE4}, std::byte{0xF0},  // and rsp,-16
    std::byte{0x48}, std::byte{0x83}, std::byte{0xEC}, std::byte{0x60},  // sub rsp,60h
    std::byte{0x33}, std::byte{0xC9},                                    // xor ecx,ecx
    std::byte{0x33}, std::byte{0xD2},                                    // xor edx,edx
    std::byte{0x4D}, std::byte{0x8D}, std::byte{0x44}, std::byte{0x24},
    std::byte{0x10},  // lea r8,[r12+10h]   (&UNICODE_STRING)
    std::byte{0x4D}, std::byte{0x8D}, std::byte{0x4C}, std::byte{0x24},
    std::byte{0x20},  // lea r9,[r12+20h]   (&module handle)
    std::byte{0x41}, std::byte{0xFF}, std::byte{0x54}, std::byte{0x24},
    std::byte{0x08},  // call qword ptr [r12+8]  (LdrLoadDll)
    std::byte{0x41}, std::byte{0x89}, std::byte{0x44}, std::byte{0x24},
    std::byte{0x44},  // mov [r12+44h],eax  (ldr status)
    std::byte{0x41}, std::byte{0xC7}, std::byte{0x44}, std::byte{0x24},
    std::byte{0x40}, std::byte{0x01}, std::byte{0x00}, std::byte{0x00},
    std::byte{0x00},                   // stage = 1
    std::byte{0x85}, std::byte{0xC0},  // test eax,eax
    std::byte{0x78}, std::byte{0x64},  // js done
    std::byte{0x49}, std::byte{0x8B}, std::byte{0x44}, std::byte{0x24},
    std::byte{0x20},                                    // mov rax,[r12+20h]  (module)
    std::byte{0x48}, std::byte{0x85}, std::byte{0xC0},  // test rax,rax
    std::byte{0x74}, std::byte{0x5A},                   // jz done
    std::byte{0x49}, std::byte{0x8D}, std::byte{0x4C}, std::byte{0x24},
    std::byte{0x50},  // lea rcx,[r12+50h]  (&BootstrapParameters)
    std::byte{0x49}, std::byte{0x8B}, std::byte{0x54}, std::byte{0x24},
    std::byte{0x28},                                    // mov rdx,[r12+28h]  (bootstrap RVA)
    std::byte{0x48}, std::byte{0x03}, std::byte{0xD0},  // add rdx,rax
    std::byte{0xFF}, std::byte{0xD2},                   // call rdx
    std::byte{0x41}, std::byte{0x89}, std::byte{0x44}, std::byte{0x24},
    std::byte{0x48},  // mov [r12+48h],eax  (bootstrap result)
    std::byte{0x41}, std::byte{0xC7}, std::byte{0x44}, std::byte{0x24},
    std::byte{0x40}, std::byte{0x02}, std::byte{0x00}, std::byte{0x00},
    std::byte{0x00},                   // stage = 2
    std::byte{0x85}, std::byte{0xC0},  // test eax,eax
    std::byte{0x75}, std::byte{0x39},  // jnz done
    std::byte{0x41}, std::byte{0xF6}, std::byte{0x44}, std::byte{0x24},
    std::byte{0x38}, std::byte{0x01},  // test byte ptr [r12+38h],1  (wait_for_ready)
    std::byte{0x74}, std::byte{0x28},  // jz ready_ok
    std::byte{0x41}, std::byte{0xBD}, std::byte{0x00}, std::byte{0x00},
    std::byte{0x00}, std::byte{0x08},  // mov r13d,8000000h  (bounded ready poll)
    std::byte{0x49}, std::byte{0x8B}, std::byte{0x5C}, std::byte{0x24},
    std::byte{0x20},  // mov rbx,[r12+20h]
    std::byte{0x49}, std::byte{0x03}, std::byte{0x5C}, std::byte{0x24},
    std::byte{0x30},                                    // add rbx,[r12+30h]  (ready RVA)
    std::byte{0xFF}, std::byte{0xD3},                   // poll: call rbx
    std::byte{0x84}, std::byte{0xC0},                   // test al,al
    std::byte{0x75}, std::byte{0x12},                   // jnz ready_ok
    std::byte{0xF3}, std::byte{0x90},                   // pause
    std::byte{0x41}, std::byte{0xFF}, std::byte{0xCD},  // dec r13d
    std::byte{0x75}, std::byte{0xF3},                   // jnz poll
    std::byte{0x41}, std::byte{0xC7}, std::byte{0x44}, std::byte{0x24},
    std::byte{0x40}, std::byte{0x04}, std::byte{0x00}, std::byte{0x00},
    std::byte{0x00},                   // stage = 4
    std::byte{0xEB}, std::byte{0x09},  // jmp done
    std::byte{0x41}, std::byte{0xC7}, std::byte{0x44}, std::byte{0x24},
    std::byte{0x40}, std::byte{0x03}, std::byte{0x00}, std::byte{0x00},
    std::byte{0x00},  // ready_ok: stage = 3
    std::byte{0x41}, std::byte{0xC7}, std::byte{0x44}, std::byte{0x24},
    std::byte{0x4C}, std::byte{0x01}, std::byte{0x00}, std::byte{0x00},
    std::byte{0x00},                   // done: done = 1
    std::byte{0xF3}, std::byte{0x90},  // spin: pause
    std::byte{0xEB}, std::byte{0xFC},  // jmp spin
};

struct alignas(8) HijackStubData {
  std::uint64_t magic{0U};
  std::uint64_t ldr_load_dll{0U};
  std::uint16_t path_length{0U};
  std::uint16_t path_capacity{0U};
  std::uint32_t path_reserved{0U};
  std::uint64_t path_buffer{0U};
  std::uint64_t module_handle{0U};
  std::uint64_t bootstrap_rva{0U};
  std::uint64_t ready_rva{0U};
  std::uint64_t flags{0U};
  std::uint32_t stage{0U};
  std::int32_t ldr_status{0};
  std::uint32_t bootstrap_result{0U};
  std::uint32_t done{0U};
  noleax::agent::windows::BootstrapParameters params{};
  // The agent path (UTF-16, NUL terminated) follows immediately afterwards.
};

inline constexpr std::uint64_t kHijackMagic = 0x4E4C58484A31ULL;  // "NLXHJ1"
inline constexpr std::uint32_t kStageLoaderReturned = 1U;
inline constexpr std::uint32_t kStageBootstrapReturned = 2U;
inline constexpr std::uint32_t kStageReady = 3U;
inline constexpr std::uint32_t kStageReadyTimeout = 4U;
inline constexpr std::uint64_t kFlagWaitForReady = 1U;

static_assert(sizeof(HijackStubData) ==
              0x50U + sizeof(noleax::agent::windows::BootstrapParameters));
static_assert(offsetof(HijackStubData, stage) == 0x40U);
static_assert(offsetof(HijackStubData, ldr_status) == 0x44U);
static_assert(offsetof(HijackStubData, bootstrap_result) == 0x48U);
static_assert(offsetof(HijackStubData, done) == 0x4CU);
static_assert(offsetof(HijackStubData, params) == 0x50U);

constexpr DWORD kThreadAccess = THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
                                THREAD_QUERY_LIMITED_INFORMATION;

[[nodiscard]] std::vector<std::uint32_t> enumerate_thread_ids(std::uint32_t process_id) {
  Handle snapshot;
  // Toolhelp snapshots race thread/process churn; ERROR_BAD_LENGTH is transient per MSDN.
  for (std::uint32_t attempt = 0U; attempt < 8U; ++attempt) {
    snapshot = Handle{CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0U)};
    if (snapshot.valid()) {
      break;
    }
    const DWORD error = GetLastError();
    if (error != ERROR_BAD_LENGTH || attempt + 1U == 8U) {
      fail("CreateToolhelp32Snapshot(threads)", error);
    }
  }
  std::vector<std::uint32_t> result;
  THREADENTRY32 entry{};
  entry.dwSize = sizeof(entry);
  if (Thread32First(snapshot.get(), &entry) == FALSE) {
    const DWORD error = GetLastError();
    if (error == ERROR_NO_MORE_FILES) {
      return result;
    }
    fail("Thread32First", error);
  }
  do {
    if (entry.th32OwnerProcessID == process_id) {
      result.push_back(entry.th32ThreadID);
    }
    entry.dwSize = sizeof(entry);
  } while (Thread32Next(snapshot.get(), &entry) != FALSE);
  if (GetLastError() != ERROR_NO_MORE_FILES) {
    fail("Thread32Next", GetLastError());
  }
  return result;
}

struct SystemModuleBases {
  std::uintptr_t ntdll{0U};
  std::uintptr_t kernel32{0U};
  std::uintptr_t kernelbase{0U};
};

struct RipClassification {
  bool usable{false};
  bool ntdll{false};
  bool system_module{false};
};

[[nodiscard]] std::uintptr_t required_remote_module_base(HANDLE process, std::uint32_t process_id,
                                                         const wchar_t* module_name) {
  const auto module = find_remote_module_resilient(process, process_id, module_name);
  if (!module.has_value()) {
    throw InjectionError{"target process does not contain the required module",
                         ERROR_MOD_NOT_FOUND};
  }
  return module->base;
}

// A hijacked thread runs the loader and the CRT on behalf of the stub, so it
// must not hold the loader or the process heap lock when it is redirected.
// The only provably lock-free suspended state is a return address inside one of
// the wait primitives below. Everything else in ntdll is rejected — notably the
// heap-growth path, which blocks inside NtAllocateVirtualMemory while holding
// the heap lock, and loader paths blocked on NtMapViewOfSection.
[[nodiscard]] std::vector<std::uintptr_t> wait_stub_return_rvas() {
  static const std::vector<std::uintptr_t> rvas = [] {
    constexpr const char* kWaitExports[] = {
        "NtWaitForSingleObject",
        "NtWaitForMultipleObjects",
        "NtDelayExecution",
        "NtWaitForKeyedEvent",
        "NtWaitForWorkViaWorkerFactory",
        "NtRemoveIoCompletion",
        "NtRemoveIoCompletionEx",
        "NtWaitForAlertByThreadId",
        "NtAlpcSendWaitReceivePort",
        "NtReplyWaitReceivePort",
        "NtWaitHigh",
        "NtWaitLow",
    };
    std::vector<std::uintptr_t> result;
    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == nullptr) {
      return result;
    }
    const auto base = reinterpret_cast<std::uintptr_t>(ntdll);
    for (const char* name : kWaitExports) {
      const FARPROC procedure = GetProcAddress(ntdll, name);
      if (procedure == nullptr) {
        continue;
      }
      const auto stub = reinterpret_cast<const std::uint8_t*>(procedure);
      for (std::size_t index = 0U; index + 1U < 32U; ++index) {
        if (stub[index] == 0x0FU && stub[index + 1U] == 0x05U) {
          result.push_back(reinterpret_cast<std::uintptr_t>(procedure) - base + index + 2U);
          break;
        }
      }
    }
    return result;
  }();
  return rvas;
}

// Usable only when the remote RIP is exactly the return address of a whitelisted
// wait primitive's syscall instruction (image RVAs are identical in the local and
// remote mappings of the same ntdll).
[[nodiscard]] bool rip_is_syscall_adjacent(std::uintptr_t rip, std::uintptr_t remote_ntdll_base) {
  if (rip < remote_ntdll_base) {
    return false;
  }
  const std::uintptr_t rva = rip - remote_ntdll_base;
  for (const std::uintptr_t return_rva : wait_stub_return_rvas()) {
    if (rva == return_rva) {
      return true;
    }
  }
  return false;
}

[[nodiscard]] RipClassification classify_rip(HANDLE process, std::uintptr_t rip,
                                             const SystemModuleBases& bases) {
  MEMORY_BASIC_INFORMATION region{};
  if (VirtualQueryEx(process, std::bit_cast<LPCVOID>(rip), &region, sizeof(region)) !=
          sizeof(region) ||
      region.State != MEM_COMMIT || region.Type != MEM_IMAGE) {
    return {};
  }
  const auto base = reinterpret_cast<std::uintptr_t>(region.AllocationBase);
  RipClassification result;
  if (base == bases.ntdll) {
    result.ntdll = true;
    result.usable = rip_is_syscall_adjacent(rip, base);
    return result;
  }
  result.usable = true;
  result.system_module = base == bases.kernel32 || base == bases.kernelbase;
  return result;
}

[[nodiscard]] int thread_score(const RipClassification& classification) noexcept {
  if (!classification.usable) {
    return 100;
  }
  if (classification.ntdll) {
    return 2;  // syscall stubs hold no locks, but prefer application frames
  }
  if (classification.system_module) {
    return 1;
  }
  return 0;
}

}  // namespace

class ThreadHijack::Impl final {
 public:
  Impl(void* process_handle, std::uint32_t process_id, const std::filesystem::path& agent_path,
       const noleax::agent::windows::BootstrapParameters& bootstrap, const Options& options)
      : process_{static_cast<HANDLE>(process_handle)}, process_id_{process_id} {
    if (process_ == nullptr || process_ == INVALID_HANDLE_VALUE || process_id_ == 0U) {
      throw InjectionError{"thread hijack parameters are invalid", ERROR_INVALID_PARAMETER};
    }
    if (!agent_path.is_absolute()) {
      throw InjectionError{"agent path must be absolute", ERROR_INVALID_PARAMETER};
    }
    std::error_code path_error;
    if (!std::filesystem::is_regular_file(agent_path, path_error) || path_error) {
      throw InjectionError{"agent DLL does not exist or is not a regular file",
                           ERROR_FILE_NOT_FOUND};
    }
    const bool standalone = bootstrap.session_token == noleax::agent::windows::kStandaloneMagic;
    if (bootstrap.structure_size != sizeof(bootstrap) ||
        bootstrap.version != noleax::agent::windows::kBootstrapVersion ||
        bootstrap.pipe_name.front() == L'\0' || bootstrap.pipe_name.back() != L'\0' ||
        (!standalone &&
         (bootstrap.connect_timeout_ms == 0U || bootstrap.controller_process_id == 0U))) {
      throw InjectionError{"agent bootstrap parameters are invalid", ERROR_INVALID_PARAMETER};
    }
    if (find_remote_module_resilient(process_, process_id_, agent_path.filename().native())
            .has_value()) {
      throw InjectionError{"an agent module with the same file name is already loaded",
                           ERROR_ALREADY_EXISTS};
    }

    // Resolve every address the stub needs before touching the thread, so a
    // local failure never leaves a modified thread behind.
    const std::uintptr_t ldr_load_dll = remote_ntdll_procedure(process_, process_id_, "LdrLoadDll");
    const HMODULE local_agent =
        LoadLibraryExW(agent_path.c_str(), nullptr, DONT_RESOLVE_DLL_REFERENCES);
    if (local_agent == nullptr) {
      fail("LoadLibraryExW(agent image)", GetLastError());
    }
    std::uintptr_t bootstrap_rva = 0U;
    std::uintptr_t ready_rva = 0U;
    try {
      bootstrap_rva = local_procedure_offset(local_agent, "noleax_agent_bootstrap");
      ready_rva = local_procedure_offset(local_agent, "noleax_agent_capture_is_ready");
    } catch (...) {
      static_cast<void>(FreeLibrary(local_agent));
      throw;
    }
    static_cast<void>(FreeLibrary(local_agent));

    const std::wstring& wide_path = agent_path.native();
    const std::size_t path_bytes = (wide_path.size() + 1U) * sizeof(wchar_t);
    if (path_bytes > std::numeric_limits<std::uint16_t>::max()) {
      throw InjectionError{"agent path is too long for UNICODE_STRING", ERROR_FILENAME_EXCED_RANGE};
    }

    acquire_thread(options.thread_handle);
    try {
      save_context();
      write_stub(wide_path, ldr_load_dll, bootstrap_rva, ready_rva, bootstrap,
                 options.wait_for_ready);
      redirect_thread();
    } catch (...) {
      restore_and_resume();
      throw;
    }
  }

  ~Impl() { abort(); }

  Impl(const Impl&) = delete;
  Impl& operator=(const Impl&) = delete;

  void start() {
    if (state_ != State::kPrepared) {
      throw InjectionError{"thread hijack cannot be started twice", ERROR_INVALID_OPERATION};
    }
    if (ResumeThread(thread_.get()) == std::numeric_limits<DWORD>::max()) {
      const DWORD error = GetLastError();
      throw InjectionError{
          "ResumeThread(hijacked thread) failed with Windows error " + std::to_string(error),
          error};
    }
    suspended_by_us_ = false;
    state_ = State::kStarted;
  }

  [[nodiscard]] std::uintptr_t finish(std::chrono::milliseconds timeout) {
    if (state_ != State::kStarted) {
      throw InjectionError{"thread hijack was not started", ERROR_INVALID_OPERATION};
    }
    HijackStubData data{};
    const bool completed = wait_for_completion(timeout, data);
    restore_and_resume();
    suspended_by_us_ = false;
    state_ = State::kFinished;
    if (!completed) {
      // Never unload on timeout: the stub writes stage only after the bootstrap export
      // returns, so no stage value proves the bootstrap was never entered. If the thread
      // was slow (for example CreateThread delayed by AV scanning), an agent worker may
      // already exist, and unloading the DLL would crash the target process. Leaking one
      // module mapping is the safe trade-off.
      throw InjectionError{
          "hijacked thread did not finish the bootstrap stub before the timeout; its context "
          "was restored",
          WAIT_TIMEOUT};
    }
    if (data.magic != kHijackMagic) {
      throw InjectionError{"hijack stub data was corrupted", ERROR_INVALID_DATA};
    }
    if (data.stage == kStageReady) {
      return data.module_handle;
    }
    if (data.stage == kStageLoaderReturned) {
      throw InjectionError{"LdrLoadDll failed with NTSTATUS " + std::to_string(data.ldr_status),
                           static_cast<std::uint32_t>(data.ldr_status)};
    }
    if (data.stage == kStageBootstrapReturned) {
      throw InjectionError{
          "agent bootstrap returned error " + std::to_string(data.bootstrap_result),
          ERROR_DLL_INIT_FAILED};
    }
    if (data.stage == kStageReadyTimeout) {
      throw InjectionError{"agent capture did not become ready inside the hijacked thread",
                           WAIT_TIMEOUT};
    }
    throw InjectionError{"hijack bootstrap stub reported an impossible stage", ERROR_INVALID_STATE};
  }

  void abort() noexcept {
    if (state_ != State::kPrepared && state_ != State::kStarted) {
      return;
    }
    restore_and_resume();
    suspended_by_us_ = false;
    state_ = State::kAborted;
  }

  [[nodiscard]] std::uint32_t thread_id() const noexcept { return thread_id_; }

 private:
  enum class State : std::uint8_t { kPrepared, kStarted, kFinished, kAborted };

  void acquire_thread(void* supplied_thread) {
    if (supplied_thread != nullptr) {
      // The launch main thread: already suspended and parked at a safe resume
      // point inside ntdll!RtlUserThreadStart. Duplicate so this object owns
      // an independent handle.
      const HANDLE raw = static_cast<HANDLE>(supplied_thread);
      HANDLE duplicate = nullptr;
      if (DuplicateHandle(GetCurrentProcess(), raw, GetCurrentProcess(), &duplicate, 0U, FALSE,
                          DUPLICATE_SAME_ACCESS) == FALSE) {
        fail("DuplicateHandle(main thread)", GetLastError());
      }
      thread_ = Handle{duplicate};
      thread_id_ = GetThreadId(duplicate);
      if (thread_id_ == 0U) {
        fail("GetThreadId(main thread)", GetLastError());
      }
      return;
    }

    SystemModuleBases bases;
    bases.ntdll = required_remote_module_base(process_, process_id_, L"ntdll.dll");
    if (const auto kernel32 = find_remote_module_resilient(process_, process_id_, L"kernel32.dll");
        kernel32.has_value()) {
      bases.kernel32 = kernel32->base;
    }
    if (const auto kernelbase =
            find_remote_module_resilient(process_, process_id_, L"kernelbase.dll");
        kernelbase.has_value()) {
      bases.kernelbase = kernelbase->base;
    }

    const std::vector<std::uint32_t> thread_ids = enumerate_thread_ids(process_id_);
    Handle best_thread;
    std::uint32_t best_id = 0U;
    int best_score = 100;
    CONTEXT candidate{};
    for (const std::uint32_t thread_id : thread_ids) {
      Handle thread{OpenThread(kThreadAccess, FALSE, thread_id)};
      if (!thread.valid()) {
        continue;  // exited or protected thread
      }
      if (SuspendThread(thread.get()) == std::numeric_limits<DWORD>::max()) {
        continue;
      }
      CONTEXT context{};
      context.ContextFlags = CONTEXT_FULL | CONTEXT_FLOATING_POINT;
      const bool context_ok = GetThreadContext(thread.get(), &context) != FALSE;
      int score = 100;
      if (context_ok) {
        const RipClassification classification = classify_rip(process_, context.Rip, bases);
        score = thread_score(classification);
      }
      if (score < best_score) {
        if (best_thread.valid()) {
          static_cast<void>(ResumeThread(best_thread.get()));  // release the previous candidate
        }
        best_thread = std::move(thread);
        best_id = thread_id;
        best_score = score;
        candidate = context;
        if (best_score == 0) {
          break;  // cannot do better than a plain application frame
        }
        continue;
      }
      static_cast<void>(ResumeThread(thread.get()));
    }
    if (!best_thread.valid()) {
      throw InjectionError{"no suitable thread for hijacking was found in the target process",
                           ERROR_NOT_FOUND};
    }
    thread_ = std::move(best_thread);
    thread_id_ = best_id;
    saved_context_ = candidate;
    context_saved_ = true;
    suspended_by_us_ = true;
  }

  void save_context() {
    if (context_saved_) {
      return;  // attach selection already captured it while the thread was suspended
    }
    // Both entry points reach here with the thread already suspended (by
    // CreateProcess for launch, by the selection loop for attach).
    saved_context_ = CONTEXT{};
    saved_context_.ContextFlags = CONTEXT_FULL | CONTEXT_FLOATING_POINT;
    if (GetThreadContext(thread_.get(), &saved_context_) == FALSE) {
      fail("GetThreadContext(hijack target)", GetLastError());
    }
    context_saved_ = true;
    suspended_by_us_ = true;
  }

  void write_stub(const std::wstring& wide_path, std::uintptr_t ldr_load_dll,
                  std::uintptr_t bootstrap_rva, std::uintptr_t ready_rva,
                  const noleax::agent::windows::BootstrapParameters& bootstrap,
                  bool wait_for_ready) {
    const std::size_t path_bytes = (wide_path.size() + 1U) * sizeof(wchar_t);
    data_memory_ = std::make_unique<RemoteMemory>(process_, sizeof(HijackStubData) + path_bytes);
    HijackStubData data{};
    data.magic = kHijackMagic;
    data.ldr_load_dll = ldr_load_dll;
    data.path_length = static_cast<std::uint16_t>(wide_path.size() * sizeof(wchar_t));
    data.path_capacity = static_cast<std::uint16_t>(path_bytes);
    data.path_buffer =
        reinterpret_cast<std::uintptr_t>(data_memory_->get()) + sizeof(HijackStubData);
    data.bootstrap_rva = bootstrap_rva;
    data.ready_rva = ready_rva;
    data.flags = wait_for_ready ? kFlagWaitForReady : 0U;
    data.params = bootstrap;
    data_memory_->write(&data, sizeof(data));
    data_memory_->write_at(sizeof(data), wide_path.c_str(), path_bytes);

    code_memory_ = std::make_unique<RemoteMemory>(process_, kHijackStub.size());
    code_memory_->write(kHijackStub.data(), kHijackStub.size());
    code_memory_->protect(PAGE_EXECUTE_READ);
  }

  void redirect_thread() {
    CONTEXT hijacked = saved_context_;
    hijacked.Rip = reinterpret_cast<std::uintptr_t>(code_memory_->get());
    hijacked.Rcx = reinterpret_cast<std::uintptr_t>(data_memory_->get());
    if (SetThreadContext(thread_.get(), &hijacked) == FALSE) {
      fail("SetThreadContext(hijack stub)", GetLastError());
    }
  }

  [[nodiscard]] bool wait_for_completion(std::chrono::milliseconds timeout,
                                         HijackStubData& data) const {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    for (;;) {
      data_memory_->read_at(offsetof(HijackStubData, done), &data.done, sizeof(data.done));
      if (data.done != 0U) {
        data_memory_->read(&data, sizeof(data));
        return true;
      }
      DWORD exit_code = 0U;
      if (GetExitCodeThread(thread_.get(), &exit_code) == FALSE || exit_code != STILL_ACTIVE) {
        data_memory_->read(&data, sizeof(data));
        return false;  // the hijacked thread died inside the stub
      }
      if (std::chrono::steady_clock::now() >= deadline) {
        data_memory_->read(&data, sizeof(data));
        return false;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds{1});
    }
  }

  void restore_and_resume() noexcept {
    if (!context_saved_) {
      return;
    }
    if (!suspended_by_us_ && SuspendThread(thread_.get()) == std::numeric_limits<DWORD>::max()) {
      return;  // the thread already exited; nothing left to restore
    }
    static_cast<void>(SetThreadContext(thread_.get(), &saved_context_));
    static_cast<void>(ResumeThread(thread_.get()));
    context_saved_ = false;
  }

  HANDLE process_{nullptr};
  std::uint32_t process_id_{0U};
  Handle thread_;
  std::uint32_t thread_id_{0U};
  bool suspended_by_us_{false};
  bool context_saved_{false};
  CONTEXT saved_context_{};
  std::unique_ptr<RemoteMemory> code_memory_;
  std::unique_ptr<RemoteMemory> data_memory_;
  State state_{State::kPrepared};
};

ThreadHijack::ThreadHijack(void* process_handle, std::uint32_t process_id,
                           const std::filesystem::path& agent_path,
                           const noleax::agent::windows::BootstrapParameters& bootstrap,
                           const Options& options)
    : impl_{std::make_unique<Impl>(process_handle, process_id, agent_path, bootstrap, options)} {}

ThreadHijack::~ThreadHijack() = default;

void ThreadHijack::start() { impl_->start(); }

std::uintptr_t ThreadHijack::finish(std::chrono::milliseconds timeout) {
  return impl_->finish(timeout);
}

void ThreadHijack::abort() noexcept { impl_->abort(); }

std::uint32_t ThreadHijack::thread_id() const noexcept { return impl_->thread_id(); }

}  // namespace noleax::controller::windows
