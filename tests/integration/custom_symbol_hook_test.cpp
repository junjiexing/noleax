#include "noleax/controller/windows/controller.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
// clang-format off: tlhelp32.h requires the Windows base types.
#include <windows.h>
#include <tlhelp32.h>
// clang-format on

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <exception>
#include <filesystem>
#include <fstream>
#include <ios>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "noleax/analyzer/event_stream.hpp"
#include "noleax/analyzer/symbolizer.hpp"
#include "noleax/analyzer/trace_metadata.hpp"
#include "noleax/controller/windows/process.hpp"
#include "noleax/ipc/protocol.hpp"
#include "noleax/trace/custom_hook.hpp"
#include "noleax/trace/event.hpp"
#include "support/loaded_image.hpp"

namespace {

using namespace std::chrono_literals;

struct ScenarioFailure {
  int code;
  std::string message;
};

#define NLX_REQUIRE(condition, code, message) \
  do {                                        \
    if (!(condition)) {                       \
      throw ScenarioFailure{code, message};   \
    }                                         \
  } while (false)

[[nodiscard]] bool wait_for_marker(const std::filesystem::path& path,
                                   std::chrono::milliseconds timeout) {
  const ULONGLONG deadline = GetTickCount64() + static_cast<ULONGLONG>(timeout.count());
  std::error_code error;
  do {
    if (std::filesystem::exists(path, error) && !error) {
      return true;
    }
    Sleep(10U);
  } while (GetTickCount64() < deadline);
  return false;
}

void write_marker(const std::filesystem::path& path, std::string_view content) {
  std::ofstream output{path, std::ios::binary | std::ios::trunc};
  output << content;
}

void remove_markers(const std::filesystem::path& prefix) {
  static constexpr std::wstring_view kSuffixes[] = {L".ready",  L".go",   L".go2",
                                                    L".loaded", L".done", L".exit"};
  for (const auto suffix : kSuffixes) {
    std::error_code error;
    static_cast<void>(std::filesystem::remove(
        prefix.parent_path() / (prefix.filename().wstring() + std::wstring{suffix}), error));
  }
}

[[nodiscard]] bool module_present(std::uint32_t process_id, const wchar_t* module_name) {
  const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, process_id);
  if (snapshot == INVALID_HANDLE_VALUE) {
    return true;  // fail-closed: cannot prove absence
  }
  MODULEENTRY32W entry{};
  entry.dwSize = sizeof(entry);
  bool found = false;
  for (BOOL scanning = Module32FirstW(snapshot, &entry); scanning != FALSE && !found;
       scanning = Module32NextW(snapshot, &entry)) {
    const wchar_t* base = wcsrchr(entry.szExePath, L'\\');
    const wchar_t* name = base != nullptr ? base + 1 : entry.szExePath;
    found = _wcsicmp(name, module_name) == 0;
  }
  static_cast<void>(CloseHandle(snapshot));
  return found;
}

struct CollectedEvents {
  std::vector<noleax::trace::Event> allocations;
  std::vector<noleax::trace::Event> reallocations;
  std::vector<noleax::trace::Event> frees;
  std::vector<noleax::trace::Event> builtin_allocations;
  std::vector<noleax::trace::CustomHookDefinition> definitions;
  noleax::analyzer::EventStreamResult stream;
};

[[nodiscard]] CollectedEvents collect_events(const std::filesystem::path& trace_path) {
  CollectedEvents collected;
  std::ifstream input{trace_path, std::ios::binary};
  noleax::analyzer::EventStreamCallbacks callbacks;
  callbacks.on_custom_hook_definition =
      [&collected](const noleax::trace::CustomHookDefinition& definition) {
        collected.definitions.push_back(definition);
      };
  callbacks.on_event = [&collected](const noleax::trace::Event& event) {
    const bool custom = event.header.api_id >= noleax::trace::kCustomHookApiIdBase;
    if (const auto* allocation = std::get_if<noleax::trace::AllocationEvent>(&event.payload)) {
      static_cast<void>(allocation);
      (custom ? collected.allocations : collected.builtin_allocations).push_back(event);
    } else if (std::holds_alternative<noleax::trace::ReallocationEvent>(event.payload) && custom) {
      collected.reallocations.push_back(event);
    } else if (std::holds_alternative<noleax::trace::FreeEvent>(event.payload) && custom) {
      collected.frees.push_back(event);
    }
  };
  collected.stream = noleax::analyzer::analyze_event_stream(input, callbacks);
  return collected;
}

[[nodiscard]] bool has_allocation_size(const std::vector<noleax::trace::Event>& events,
                                       std::uint64_t size) {
  for (const auto& event : events) {
    if (std::get<noleax::trace::AllocationEvent>(event.payload).requested_size == size &&
        event.header.status == noleax::trace::EventStatus::kSuccess) {
      return true;
    }
  }
  return false;
}

[[nodiscard]] bool has_builtin_size(const std::vector<noleax::trace::Event>& events,
                                    std::uint64_t size) {
  for (const auto& event : events) {
    if (std::get<noleax::trace::AllocationEvent>(event.payload).requested_size == size) {
      return true;
    }
  }
  return false;
}

[[nodiscard]] noleax::controller::windows::CaptureOptions make_capture(
    const std::filesystem::path& agent, const std::filesystem::path& trace_path,
    std::vector<noleax::ipc::CustomHookSpec> hooks, bool unload_on_stop = false) {
  noleax::controller::windows::CaptureOptions capture;
  capture.agent_path = agent;
  capture.timeout = 10s;
  capture.start.hook_profile = noleax::ipc::HookProfile::kWindowsNative;
  capture.start.maximum_stack_depth = 16U;
  capture.start.buffer_size = 8U * 1024U * 1024U;
  capture.start.maximum_trace_size = 64U * 1024U * 1024U;
  capture.start.flush_interval_ns = 5U * 1000U * 1000U;
  capture.start.trace_path_utf8 = noleax::controller::windows::wide_to_utf8(trace_path.native());
  capture.start.unload_on_stop = unload_on_stop;
  capture.start.custom_hooks = std::move(hooks);
  return capture;
}

[[nodiscard]] noleax::ipc::CustomHookRoleSpec export_role(std::string name) {
  noleax::ipc::CustomHookRoleSpec role;
  role.locator = noleax::ipc::CustomHookLocator::kExport;
  role.export_name = std::move(name);
  return role;
}

[[nodiscard]] noleax::ipc::CustomHookRoleSpec rva_role(std::uint64_t rva) {
  noleax::ipc::CustomHookRoleSpec role;
  role.locator = noleax::ipc::CustomHookLocator::kRva;
  role.rva = rva;
  return role;
}

[[nodiscard]] noleax::ipc::CustomHookSpec fixture_hook(std::string module, std::string alloc_export,
                                                       std::string label) {
  noleax::ipc::CustomHookSpec hook;
  hook.module = std::move(module);
  hook.alloc = export_role(std::move(alloc_export));
  hook.realloc = export_role("my_realloc");
  hook.free = export_role("my_free");
  hook.size_arg = 1U;
  hook.label = std::move(label);
  return hook;
}

struct ScenarioContext {
  std::filesystem::path agent;
  std::filesystem::path target;
  std::filesystem::path static_target;
  std::filesystem::path noleax_exe;
  std::filesystem::path fixture_dir;
  std::filesystem::path workdir;

  [[nodiscard]] std::filesystem::path fixture(const wchar_t* name) const {
    return fixture_dir / name;
  }
};

[[nodiscard]] std::uint32_t run_and_wait(const std::filesystem::path& executable,
                                         const std::vector<std::wstring>& arguments,
                                         const std::filesystem::path* log_path = nullptr) {
  std::wstring command = L"\"" + executable.native() + L"\"";
  for (const auto& argument : arguments) {
    command.push_back(L' ');
    command.append(noleax::controller::windows::quote_windows_argument(argument));
  }
  std::vector<wchar_t> mutable_command{command.begin(), command.end()};
  mutable_command.push_back(L'\0');
  HANDLE log_handle = nullptr;
  SECURITY_ATTRIBUTES security{};
  security.nLength = sizeof(security);
  security.bInheritHandle = TRUE;
  if (log_path != nullptr) {
    log_handle = CreateFileW(log_path->c_str(), GENERIC_WRITE, FILE_SHARE_READ, &security,
                             CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (log_handle == nullptr) {
      throw ScenarioFailure{70, "cannot create the child log file"};
    }
  }
  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  if (log_handle != nullptr) {
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    startup.hStdOutput = log_handle;
    startup.hStdError = log_handle;
  }
  PROCESS_INFORMATION process{};
  const BOOL created = CreateProcessW(nullptr, mutable_command.data(), nullptr, nullptr, TRUE,
                                      CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT, nullptr,
                                      nullptr, &startup, &process);
  if (log_handle != nullptr) {
    static_cast<void>(CloseHandle(log_handle));
  }
  if (created == FALSE) {
    throw ScenarioFailure{70, "cannot start " + executable.filename().string()};
  }
  const DWORD wait = WaitForSingleObject(process.hProcess, 120'000U);
  DWORD exit_code = 255U;
  if (wait != WAIT_OBJECT_0 || GetExitCodeProcess(process.hProcess, &exit_code) == FALSE) {
    static_cast<void>(TerminateProcess(process.hProcess, 99U));
  }
  static_cast<void>(CloseHandle(process.hThread));
  static_cast<void>(CloseHandle(process.hProcess));
  if (wait != WAIT_OBJECT_0) {
    throw ScenarioFailure{71, executable.filename().string() + " did not exit in time"};
  }
  return exit_code;
}

class TargetProcess {
 public:
  TargetProcess(const ScenarioContext& context, const std::string& name, std::string mode = "basic")
      : prefix_{context.workdir / name} {
    remove_markers(prefix_);
    process_ = noleax::controller::windows::SuspendedProcess::create(
        context.target,
        {noleax::controller::windows::wide_to_utf8(context.fixture_dir.native()),
         noleax::controller::windows::wide_to_utf8(prefix_.native()), std::move(mode)},
        context.target.parent_path());
    process_.resume_main_thread();
  }

  TargetProcess(const TargetProcess&) = delete;
  TargetProcess& operator=(const TargetProcess&) = delete;

  ~TargetProcess() {
    std::error_code error;
    static_cast<void>(std::filesystem::remove(exit_marker(), error));
    if (process_.process_id() != 0U) {
      process_.terminate(0U);
    }
  }

  [[nodiscard]] std::filesystem::path marker(const wchar_t* suffix) const {
    return prefix_.parent_path() / (prefix_.filename().wstring() + suffix);
  }
  [[nodiscard]] std::filesystem::path exit_marker() const { return marker(L".exit"); }

  void wait_ready() {
    if (!wait_for_marker(marker(L".ready"), 10s)) {
      throw ScenarioFailure{30, "target did not signal readiness"};
    }
  }

  void go() { write_marker(marker(L".go"), "go\n"); }
  void go2() { write_marker(marker(L".go2"), "go\n"); }
  void exit() { write_marker(exit_marker(), "exit\n"); }

  [[nodiscard]] std::string wait_done() {
    if (!wait_for_marker(marker(L".done"), 10s)) {
      throw ScenarioFailure{31, "target did not finish its allocation sequence"};
    }
    std::ifstream input{marker(L".done")};
    std::string line;
    std::getline(input, line);
    return line;
  }

  [[nodiscard]] noleax::controller::windows::SuspendedProcess& process() { return process_; }
  [[nodiscard]] std::uint32_t process_id() const { return process_.process_id(); }

 private:
  std::filesystem::path prefix_;
  noleax::controller::windows::SuspendedProcess process_;
};

void check_sequence_succeeded(const std::string& done_line) {
  NLX_REQUIRE(done_line == "done=0", 32, "target allocation sequence failed: " + done_line);
}

void scenario_export(const ScenarioContext& context, bool forced = false) {
  TargetProcess target{context, forced ? "export-forced" : "export"};
  target.wait_ready();
  auto hook = fixture_hook("noleax-custom-alloc-a.dll", "my_malloc", "my_malloc");
  hook.forced = forced;
  const auto trace_path = context.workdir / (forced ? "export-forced.nlx" : "export.nlx");
  const auto capture = make_capture(context.agent, trace_path, {hook});
  auto session = noleax::controller::windows::CaptureSession::attach(target.process_id(), capture);
  target.go();
  check_sequence_succeeded(target.wait_done());
  const auto final = session.stop();
  NLX_REQUIRE(final.state == noleax::ipc::AgentState::kFinalized, 33, "capture did not finalize");

  const auto events = collect_events(trace_path);
  NLX_REQUIRE(events.definitions.size() == 1U, 34, "expected one CustomHookDefinition");
  NLX_REQUIRE(events.definitions.front().api_id == noleax::trace::kCustomHookApiIdBase, 34,
              "custom api_id does not start at the custom base");
  NLX_REQUIRE(events.definitions.front().module_name == "noleax-custom-alloc-a.dll", 34,
              "custom definition module mismatch");
  NLX_REQUIRE(events.definitions.front().label == "my_malloc", 34, "custom label mismatch");
  NLX_REQUIRE(events.allocations.size() == 3U, 35, "expected three custom allocations");
  NLX_REQUIRE(has_allocation_size(events.allocations, 0x1111U), 35, "missing 0x1111 alloc");
  NLX_REQUIRE(has_allocation_size(events.allocations, 0x2222U), 35, "missing 0x2222 alloc");
  NLX_REQUIRE(has_allocation_size(events.allocations, 0x5555U), 35, "missing leaked 0x5555 alloc");
  for (const auto& event : events.allocations) {
    NLX_REQUIRE(event.header.api_id == noleax::trace::kCustomHookApiIdBase, 36,
                "custom alloc api_id mismatch");
    const auto& allocation = std::get<noleax::trace::AllocationEvent>(event.payload);
    NLX_REQUIRE((allocation.allocation_id.value() >> 40U) == noleax::trace::kCustomHookApiIdBase,
                36, "custom allocation_id does not embed the api_id");
  }
  NLX_REQUIRE(events.reallocations.size() == 1U, 37, "expected one custom reallocation");
  {
    const auto& reallocation =
        std::get<noleax::trace::ReallocationEvent>(events.reallocations.front().payload);
    NLX_REQUIRE(reallocation.requested_size == 0x4444U, 37, "realloc size mismatch");
    NLX_REQUIRE(reallocation.effect == noleax::trace::ReallocationEffect::kNewGeneration, 37,
                "realloc effect mismatch");
  }
  NLX_REQUIRE(events.frees.size() == 1U, 38, "expected one custom free");
  // Guard recursion suppression: the fixture's internal RtlAllocateHeap calls must not be
  // recorded under the built-in API ID.
  NLX_REQUIRE(!has_builtin_size(events.builtin_allocations, 0x1111U), 39,
              "recursion suppression recorded a nested 0x1111 alloc");
  NLX_REQUIRE(!has_builtin_size(events.builtin_allocations, 0x2222U), 39,
              "recursion suppression recorded a nested 0x2222 alloc");
  NLX_REQUIRE(!has_builtin_size(events.builtin_allocations, 0x5555U), 39,
              "recursion suppression recorded a nested 0x5555 alloc");

  // Analyzer-side name resolution.
  std::ifstream input{trace_path, std::ios::binary};
  noleax::analyzer::TraceMetadata metadata;
  static_cast<void>(metadata.scan(input));
  const auto fields = metadata.metadata(events.allocations.front());
  NLX_REQUIRE(fields.api_name == "my_malloc", 40, "metadata api_name mismatch");
  NLX_REQUIRE(fields.api_module == "noleax-custom-alloc-a.dll", 40, "metadata api_module mismatch");
  std::printf("scenario=export%s ok\n", forced ? "-forced" : "");
}

void scenario_rva(const ScenarioContext& context) {
  noleax::testing::LoadedImage image{context.fixture(L"noleax-custom-alloc-a.dll")};
  noleax::ipc::CustomHookSpec hook;
  hook.module = "noleax-custom-alloc-a.dll";
  hook.alloc = rva_role(image.exported_offset("my_malloc"));
  hook.free = rva_role(image.exported_offset("my_free"));
  hook.size_arg = 1U;
  hook.label = "my_malloc";

  TargetProcess target{context, "rva"};
  target.wait_ready();
  const auto trace_path = context.workdir / "rva.nlx";
  const auto capture = make_capture(context.agent, trace_path, {hook});
  auto session = noleax::controller::windows::CaptureSession::attach(target.process_id(), capture);
  target.go();
  check_sequence_succeeded(target.wait_done());
  const auto final = session.stop();
  NLX_REQUIRE(final.state == noleax::ipc::AgentState::kFinalized, 41, "capture did not finalize");

  const auto events = collect_events(trace_path);
  NLX_REQUIRE(events.allocations.size() == 3U, 42, "expected three custom allocations (RVA)");
  NLX_REQUIRE(events.reallocations.empty(), 42, "no realloc role was declared for the RVA hook");
  NLX_REQUIRE(events.frees.size() == 1U, 42, "expected one custom free (RVA)");
  std::printf("scenario=rva ok\n");
}

void scenario_pdb(const ScenarioContext& context) {
  const auto fixture_path = context.fixture(L"noleax-custom-alloc-a.dll");
  noleax::testing::LoadedImage image{fixture_path};
  noleax::analyzer::SymbolizerOptions options;
  options.search_paths = {context.fixture_dir};
  noleax::analyzer::OfflineSymbolizer symbolizer{options};
  noleax::analyzer::SymbolModule module;
  module.module_id = noleax::trace::ModuleId{1U};
  module.image_size = image.size();
  module.image_path = fixture_path;
  const auto registered = symbolizer.register_module(module);
  NLX_REQUIRE(registered.status == noleax::analyzer::SymbolModuleStatus::kSymbolsLoaded, 43,
              "fixture PDB was not loaded");
  const auto alloc_rva = symbolizer.resolve_symbol(module.module_id, "my_internal_alloc");
  const auto free_rva = symbolizer.resolve_symbol(module.module_id, "my_internal_free");
  NLX_REQUIRE(alloc_rva.has_value() && free_rva.has_value(), 43,
              "PDB-only symbols were not resolved");
  symbolizer.unregister_module(module.module_id);

  noleax::ipc::CustomHookSpec hook;
  hook.module = "noleax-custom-alloc-a.dll";
  hook.alloc = rva_role(*alloc_rva);
  hook.free = rva_role(*free_rva);
  hook.label = "my_internal_alloc";
  if (registered.image_identity.has_value()) {
    hook.image_identity = noleax::ipc::CustomHookImageIdentity{
        registered.image_identity->timestamp, registered.image_identity->checksum,
        registered.image_identity->image_size};
  }

  TargetProcess target{context, "pdb"};
  target.wait_ready();
  const auto trace_path = context.workdir / "pdb.nlx";
  const auto capture = make_capture(context.agent, trace_path, {hook});
  auto session = noleax::controller::windows::CaptureSession::attach(target.process_id(), capture);
  target.go();
  check_sequence_succeeded(target.wait_done());
  const auto final = session.stop();
  NLX_REQUIRE(final.state == noleax::ipc::AgentState::kFinalized, 44, "capture did not finalize");

  const auto events = collect_events(trace_path);
  NLX_REQUIRE(events.allocations.size() == 1U, 45, "expected one internal allocation (PDB)");
  NLX_REQUIRE(has_allocation_size(events.allocations, 0x6666U), 45,
              "missing 0x6666 internal alloc");
  NLX_REQUIRE(events.frees.size() == 1U, 45, "expected one internal free (PDB)");
  std::printf("scenario=pdb ok\n");
}

void scenario_mappings(const ScenarioContext& context) {
  noleax::ipc::CustomHookSpec calloc_hook;
  calloc_hook.module = "noleax-custom-alloc-b.dll";
  calloc_hook.alloc = export_role("my_calloc");
  calloc_hook.free = export_role("my_free");
  calloc_hook.calloc = true;
  calloc_hook.count_arg = std::uint8_t{0U};
  calloc_hook.size_arg = 1U;
  calloc_hook.label = "my_calloc";

  noleax::ipc::CustomHookSpec sized_hook;
  sized_hook.module = "noleax-custom-alloc-c.dll";
  sized_hook.alloc = export_role("my_xalloc");
  sized_hook.free = export_role("my_free_size");
  sized_hook.size_arg = 1U;
  sized_hook.result_arg = std::uint8_t{0U};
  sized_hook.free_size_arg = std::uint8_t{1U};
  sized_hook.label = "my_xalloc";

  TargetProcess target{context, "mappings"};
  target.wait_ready();
  const auto trace_path = context.workdir / "mappings.nlx";
  const auto capture = make_capture(context.agent, trace_path, {calloc_hook, sized_hook});
  auto session = noleax::controller::windows::CaptureSession::attach(target.process_id(), capture);
  target.go();
  check_sequence_succeeded(target.wait_done());
  const auto final = session.stop();
  NLX_REQUIRE(final.state == noleax::ipc::AgentState::kFinalized, 46, "capture did not finalize");

  const auto events = collect_events(trace_path);
  NLX_REQUIRE(events.definitions.size() == 2U, 47, "expected two CustomHookDefinitions");
  NLX_REQUIRE(events.definitions.at(1U).api_id == noleax::trace::kCustomHookApiIdBase + 1U, 47,
              "second custom api_id mismatch");
  NLX_REQUIRE(events.allocations.size() == 2U, 48, "expected two mapped allocations");
  // calloc(4, 0x100) must record 0x400 bytes; my_xalloc records the out-param result.
  NLX_REQUIRE(has_allocation_size(events.allocations, 0x400U), 48,
              "calloc mapping recorded a wrong size");
  NLX_REQUIRE(has_allocation_size(events.allocations, 0x3333U), 48,
              "out-param mapping recorded a wrong size");
  NLX_REQUIRE(events.frees.size() == 2U, 48, "expected two mapped frees");
  for (const auto& event : events.frees) {
    NLX_REQUIRE(event.header.status == noleax::trace::EventStatus::kSuccess, 48,
                "mapped free was not matched to its allocation");
  }
  std::printf("scenario=mappings ok\n");
}

void scenario_wait_module(const ScenarioContext& context) {
  TargetProcess target{context, "wait-module", "late"};
  target.wait_ready();
  auto hook = fixture_hook("noleax-custom-alloc-a.dll", "my_malloc", "my_malloc");
  hook.wait_module_ms = 10'000U;
  const auto trace_path = context.workdir / "wait-module.nlx";
  const auto capture = make_capture(context.agent, trace_path, {hook});
  // Let the target load the module while the agent is polling for it.
  target.go();
  auto session = noleax::controller::windows::CaptureSession::attach(target.process_id(), capture);
  target.go2();
  check_sequence_succeeded(target.wait_done());
  const auto final = session.stop();
  NLX_REQUIRE(final.state == noleax::ipc::AgentState::kFinalized, 49,
              "wait_module capture did not finalize");
  const auto events = collect_events(trace_path);
  NLX_REQUIRE(events.allocations.size() == 3U, 49, "wait_module capture lost allocations");
  std::printf("scenario=wait-module ok\n");
}

void scenario_missing_module(const ScenarioContext& context) {
  TargetProcess target{context, "missing-module"};
  target.wait_ready();
  auto hook = fixture_hook("noleax-missing-zzz.dll", "my_malloc", "my_malloc");
  const auto trace_path = context.workdir / "missing-module.nlx";
  const auto capture = make_capture(context.agent, trace_path, {hook});
  std::string error_message;
  try {
    auto session =
        noleax::controller::windows::CaptureSession::attach(target.process_id(), capture);
    error_message =
        "attach unexpectedly succeeded (pid " + std::to_string(session.process_id()) + ")";
  } catch (const std::exception& error) {
    error_message = error.what();
  }
  NLX_REQUIRE(error_message.find("noleax-missing-zzz.dll") != std::string::npos, 50,
              "missing-module error does not name the module: " + error_message);
  // The failed install must not damage the target: it still runs its sequence to completion
  // and exits cleanly when asked.
  target.go();
  check_sequence_succeeded(target.wait_done());
  const auto events = collect_events(trace_path);
  NLX_REQUIRE(events.allocations.empty() && events.reallocations.empty() && events.frees.empty(),
              51, "a failed install unexpectedly recorded custom events");
  std::printf("scenario=missing-module ok\n");
}

void scenario_missing_export(const ScenarioContext& context) {
  TargetProcess target{context, "missing-export"};
  target.wait_ready();
  auto hook = fixture_hook("noleax-custom-alloc-a.dll", "no_such_export", "no_such_export");
  const auto trace_path = context.workdir / "missing-export.nlx";
  const auto capture = make_capture(context.agent, trace_path, {hook});
  std::string error_message;
  try {
    auto session =
        noleax::controller::windows::CaptureSession::attach(target.process_id(), capture);
    error_message =
        "attach unexpectedly succeeded (pid " + std::to_string(session.process_id()) + ")";
  } catch (const std::exception& error) {
    error_message = error.what();
  }
  NLX_REQUIRE(error_message.find("no_such_export") != std::string::npos, 52,
              "missing-export error does not name the export: " + error_message);
  std::printf("scenario=missing-export ok\n");
}

void scenario_unload_on_stop(const ScenarioContext& context) {
  TargetProcess target{context, "unload"};
  target.wait_ready();
  auto hook = fixture_hook("noleax-custom-alloc-a.dll", "my_malloc", "my_malloc");
  const auto trace_path = context.workdir / "unload.nlx";
  const auto capture = make_capture(context.agent, trace_path, {hook}, true);
  auto session = noleax::controller::windows::CaptureSession::attach(target.process_id(), capture);
  target.go();
  check_sequence_succeeded(target.wait_done());
  const auto final = session.stop();
  NLX_REQUIRE(final.state == noleax::ipc::AgentState::kFinalized, 53,
              "unload-on-stop capture did not finalize");
  const ULONGLONG deadline = GetTickCount64() + 10'000U;
  while (module_present(target.process_id(), L"noleax-agent.dll") && GetTickCount64() < deadline) {
    Sleep(100U);
  }
  NLX_REQUIRE(!module_present(target.process_id(), L"noleax-agent.dll"), 53,
              "agent did not unload after stop");
  const auto events = collect_events(trace_path);
  NLX_REQUIRE(events.allocations.size() == 3U, 53, "unload-on-stop capture lost allocations");
  std::printf("scenario=unload-on-stop ok\n");
}

void scenario_min_size(const ScenarioContext& context) {
  TargetProcess target{context, "min-size"};
  target.wait_ready();
  auto hook = fixture_hook("noleax-custom-alloc-a.dll", "my_malloc", "my_malloc");
  const auto trace_path = context.workdir / "min-size.nlx";
  auto capture = make_capture(context.agent, trace_path, {hook});
  capture.start.minimum_capture_size = 0x2000U;
  auto session = noleax::controller::windows::CaptureSession::attach(target.process_id(), capture);
  target.go();
  check_sequence_succeeded(target.wait_done());
  const auto final = session.stop();
  NLX_REQUIRE(final.state == noleax::ipc::AgentState::kFinalized, 54,
              "min-size capture did not finalize");

  const auto events = collect_events(trace_path);
  NLX_REQUIRE(events.allocations.size() == 2U, 54, "min-size filter dropped the wrong allocs");
  NLX_REQUIRE(!has_allocation_size(events.allocations, 0x1111U), 54,
              "min-size filter let a small alloc through");
  NLX_REQUIRE(has_allocation_size(events.allocations, 0x2222U), 54, "missing 0x2222 alloc");
  NLX_REQUIRE(events.stream.statistics.has_value(), 54, "capture statistics are missing");
  const auto& per_api = events.stream.statistics->per_api;
  const auto custom_api =
      std::find_if(per_api.begin(), per_api.end(), [](const noleax::trace::ApiStatistics& api) {
        return api.api_id == noleax::trace::kCustomHookApiIdBase;
      });
  NLX_REQUIRE(custom_api != per_api.end(), 54, "custom API statistics are missing");
  NLX_REQUIRE(custom_api->filtered_before_queue == 1U, 54,
              "min-size filter did not count the filtered call");
  std::printf("scenario=min-size ok\n");
}

// A spawned child the test can coordinate through marker files while it keeps running.
class ChildProcess {
 public:
  ChildProcess(const std::filesystem::path& executable, const std::vector<std::wstring>& arguments,
               const std::filesystem::path* log_path = nullptr) {
    std::wstring command = L"\"" + executable.native() + L"\"";
    for (const auto& argument : arguments) {
      command.push_back(L' ');
      command.append(noleax::controller::windows::quote_windows_argument(argument));
    }
    std::vector<wchar_t> mutable_command{command.begin(), command.end()};
    mutable_command.push_back(L'\0');
    HANDLE log_handle = nullptr;
    SECURITY_ATTRIBUTES security{};
    security.nLength = sizeof(security);
    security.bInheritHandle = TRUE;
    if (log_path != nullptr) {
      log_handle = CreateFileW(log_path->c_str(), GENERIC_WRITE, FILE_SHARE_READ, &security,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
      if (log_handle == nullptr) {
        throw ScenarioFailure{70, "cannot create the child log file"};
      }
    }
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    if (log_handle != nullptr) {
      startup.dwFlags = STARTF_USESTDHANDLES;
      startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
      startup.hStdOutput = log_handle;
      startup.hStdError = log_handle;
    }
    PROCESS_INFORMATION process{};
    const BOOL created = CreateProcessW(nullptr, mutable_command.data(), nullptr, nullptr, FALSE,
                                        CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT, nullptr,
                                        nullptr, &startup, &process);
    if (log_handle != nullptr) {
      static_cast<void>(CloseHandle(log_handle));
    }
    if (created == FALSE) {
      throw ScenarioFailure{70, "cannot start " + executable.filename().string()};
    }
    process_ = process.hProcess;
    static_cast<void>(CloseHandle(process.hThread));
  }

  ChildProcess(const ChildProcess&) = delete;
  ChildProcess& operator=(const ChildProcess&) = delete;

  ~ChildProcess() {
    if (process_ != nullptr) {
      static_cast<void>(TerminateProcess(process_, 1U));
      static_cast<void>(CloseHandle(process_));
    }
  }

  [[nodiscard]] std::uint32_t wait(std::uint32_t timeout_ms) {
    const DWORD wait = WaitForSingleObject(process_, timeout_ms);
    if (wait != WAIT_OBJECT_0) {
      throw ScenarioFailure{71, "patched target did not exit in time"};
    }
    DWORD exit_code = 255U;
    if (GetExitCodeProcess(process_, &exit_code) == FALSE) {
      throw ScenarioFailure{71, "cannot query the patched target exit code"};
    }
    static_cast<void>(CloseHandle(process_));
    process_ = nullptr;
    return exit_code;
  }

 private:
  HANDLE process_{nullptr};
};

void scenario_patch_standalone(const ScenarioContext& context) {
  const auto patch_dir = context.workdir / "patch-standalone";
  std::error_code path_error;
  std::filesystem::create_directories(patch_dir, path_error);
  const auto patched_exe = patch_dir / "patched-target.exe";
  const auto agent_copy = patch_dir / "noleax-agent.dll";
  static_cast<void>(std::filesystem::remove(patched_exe, path_error));
  static_cast<void>(std::filesystem::remove(agent_copy, path_error));
  static_cast<void>(std::filesystem::remove(patch_dir / "noleax-agent.toml", path_error));
  std::filesystem::copy_file(context.agent, agent_copy,
                             std::filesystem::copy_options::overwrite_existing, path_error);
  NLX_REQUIRE(!path_error, 72, "cannot stage the agent beside the patched exe");
  for (const wchar_t* name :
       {L"noleax-custom-alloc-a.dll", L"noleax-custom-alloc-b.dll", L"noleax-custom-alloc-c.dll"}) {
    std::filesystem::copy_file(context.fixture(name), patch_dir / name,
                               std::filesystem::copy_options::overwrite_existing, path_error);
    NLX_REQUIRE(!path_error, 72, "cannot stage the fixture modules");
  }
  const auto config_path = context.workdir / "patch-standalone.toml";
  {
    std::ofstream config{config_path, std::ios::binary | std::ios::trunc};
    config << "schema_version = 1\n"
              "\n"
              "[patch]\n"
              "input = \""
           << noleax::controller::windows::wide_to_utf8(context.static_target.generic_wstring())
           << "\"\n"
              "output = \""
           << noleax::controller::windows::wide_to_utf8(patched_exe.generic_wstring())
           << "\"\n"
              "standalone = true\n"
              "\n"
              "[symbols]\n"
              "paths = [\""
           << noleax::controller::windows::wide_to_utf8(context.fixture_dir.generic_wstring())
           << "\"]\n"
              "\n"
              "[[custom_hooks]]\n"
              "module = \"noleax-custom-alloc-a.dll\"\n"
              "alloc_pdb = \"noleax-custom-alloc-a!my_internal_alloc\"\n"
              "free_pdb = \"noleax-custom-alloc-a!my_internal_free\"\n"
              "wait_module = \"60s\"\n";
  }
  const std::uint32_t patch_exit =
      run_and_wait(context.noleax_exe, {L"--config", config_path.native(), L"patch"});
  NLX_REQUIRE(patch_exit == 0U, 73, "noleax patch failed to bake the custom hook configuration");
  NLX_REQUIRE(std::filesystem::exists(patch_dir / "noleax-agent.toml", path_error), 73,
              "noleax patch did not write the baked agent configuration");

  // The patched copy runs without a controller: the agent reads the baked configuration and
  // hooks the PDB-only internal functions through their baked RVAs. wait_module polls for the
  // fixture module only after the agent has finished installing the built-in profile, which
  // under CI antivirus scanning takes several seconds. There is no deterministic ready signal
  // in sibling-config mode, so the go marker uses a generous settle window after ready.
  const auto prefix = patch_dir / "patched";
  const auto run_log = patch_dir / "patched-standalone.log";
  static_cast<void>(std::filesystem::remove(run_log, path_error));
  remove_markers(prefix);
  ChildProcess child{patched_exe, {patch_dir.native(), prefix.native(), L"basic"}, &run_log};
  if (!wait_for_marker(prefix.parent_path() / (prefix.filename().wstring() + L".ready"), 60s)) {
    throw ScenarioFailure{74, "patched target did not become ready"};
  }
  Sleep(8'000U);
  write_marker(prefix.parent_path() / (prefix.filename().wstring() + L".go"), "go\n");
  if (!wait_for_marker(prefix.parent_path() / (prefix.filename().wstring() + L".done"), 30s)) {
    throw ScenarioFailure{74, "patched target did not finish its allocation sequence"};
  }
  Sleep(1'000U);
  write_marker(prefix.parent_path() / (prefix.filename().wstring() + L".exit"), "exit\n");
  const std::uint32_t target_exit = child.wait(30'000U);
  NLX_REQUIRE(target_exit == 0U, 74,
              "patched target sequence failed: " + std::to_string(target_exit));

  const auto events = collect_events(patch_dir / "patched-target.nlx");
  NLX_REQUIRE(events.definitions.size() == 1U, 75, "expected one baked CustomHookDefinition");
  NLX_REQUIRE(events.definitions.front().label.find("noleax-custom-alloc-a.dll+0x") == 0U, 75,
              "baked definition label mismatch: " + events.definitions.front().label);
  const auto log_tail = [run_log] {
    std::ifstream input{run_log, std::ios::binary};
    std::string content{std::istreambuf_iterator<char>{input}, std::istreambuf_iterator<char>{}};
    return content.size() > 400U ? content.substr(content.size() - 400U) : content;
  };
  const auto trace_state = [&events] {
    return "builtin=" + std::to_string(events.builtin_allocations.size()) +
           " custom-defs=" + std::to_string(events.definitions.size()) + " eot=" +
           std::to_string(events.stream.end_of_trace.has_value()
                              ? static_cast<int>(events.stream.end_of_trace->normal_stop)
                              : -1) +
           " events=" + std::to_string(events.stream.event_count);
  };
  NLX_REQUIRE(
      events.allocations.size() == 1U, 75,
      "expected one baked internal allocation (" + trace_state() + "); agent log: " + log_tail());
  NLX_REQUIRE(has_allocation_size(events.allocations, 0x6666U), 75,
              "baked RVA hook missed the internal alloc");
  NLX_REQUIRE(events.frees.size() == 1U, 75, "expected one baked internal free");

  // A standalone configuration carrying an unresolved PDB symbol must fail loudly at agent
  // start instead of being silently ignored.
  {
    std::ofstream agent_config{patch_dir / "noleax-agent.toml", std::ios::binary | std::ios::trunc};
    agent_config << "schema_version = 1\n"
                    "\n"
                    "[[custom_hooks]]\n"
                    "module = \"noleax-custom-alloc-a.dll\"\n"
                    "alloc_pdb = \"noleax-custom-alloc-a!my_internal_alloc\"\n"
                    "free_pdb = \"noleax-custom-alloc-a!my_internal_free\"\n";
  }
  const auto pdb_prefix = patch_dir / "patched-pdb";
  remove_markers(pdb_prefix);
  write_marker(pdb_prefix.parent_path() / (pdb_prefix.filename().wstring() + L".go"), "go\n");
  write_marker(pdb_prefix.parent_path() / (pdb_prefix.filename().wstring() + L".exit"), "exit\n");
  const auto log_path = patch_dir / "patched-pdb.log";
  const std::uint32_t pdb_exit =
      run_and_wait(patched_exe, {patch_dir.native(), pdb_prefix.native(), L"basic"}, &log_path);
  NLX_REQUIRE(pdb_exit == 0U, 76, "the target must run normally with capture disabled");
  std::ifstream log_input{log_path, std::ios::binary};
  const std::string log{std::istreambuf_iterator<char>{log_input},
                        std::istreambuf_iterator<char>{}};
  NLX_REQUIRE(log.find("unresolved PDB symbol") != std::string::npos, 76,
              "agent did not reject the unresolved PDB symbol: " + log);
  std::printf("scenario=patch-standalone ok\n");
}

int run(int argc, char* argv[]) {
  if (argc != 7) {
    return 2;
  }
  ScenarioContext context;
  context.agent = std::filesystem::absolute(argv[1]);
  context.target = std::filesystem::absolute(argv[2]);
  context.noleax_exe = std::filesystem::absolute(argv[3]);
  context.fixture_dir = std::filesystem::absolute(argv[4]);
  context.workdir = std::filesystem::absolute(argv[5]);
  context.static_target = std::filesystem::absolute(argv[6]);
  std::error_code path_error;
  std::filesystem::create_directories(context.workdir, path_error);

  scenario_export(context);
  scenario_export(context, true);
  scenario_rva(context);
  scenario_pdb(context);
  scenario_mappings(context);
  scenario_min_size(context);
  scenario_wait_module(context);
  scenario_missing_module(context);
  scenario_missing_export(context);
  scenario_unload_on_stop(context);
  scenario_patch_standalone(context);

  std::printf(
      "status=ok export=1 forced=1 rva=1 pdb=1 mappings=1 min-size=1 wait-module=1 "
      "missing-module=1 missing-export=1 unload=1 patch-standalone=1\n");
  return 0;
}

}  // namespace

int main(int argc, char* argv[]) {
  try {
    return run(argc, argv);
  } catch (const ScenarioFailure& failure) {
    std::fprintf(stderr, "custom symbol hook scenario failed (%d): %s\n", failure.code,
                 failure.message.c_str());
    return failure.code;
  } catch (const std::exception& error) {
    std::fprintf(stderr, "custom symbol hook test exception: %s\n", error.what());
    return 60;
  }
}
