#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <vector>

namespace noleax::controller::linux {

// Ptrace attach injector (docs/LINUX_PORT_PLAN.md §M6): seizes a RUNNING process with
// PTRACE_SEIZE, hijacks one safely-parked thread for a few milliseconds, and uses it to
// dlopen the agent image and call its attach bootstrap export. The thread-selection rules
// (never a thread parked inside ld.so, prefer a thread blocked in a syscall) follow the
// thread-hijack lessons of docs/THREAD_HIJACK_INJECTION.md; every wait is bounded and any
// failure restores the original state before the error propagates, so the target is never
// left seized.
//
// One RWX stub page (4 KiB) is deliberately left mapped inside the target: it holds the
// call stub, the agent path string, and the bootstrap parameter blob. Unmapping it would
// require running a final munmap stub whose own int3 lives on the page being unmapped;
// the page stays, documented, exactly like the loaded agent image itself.
class PtraceInjector final {
 public:
  // Seizes the target process, injects agent_path via dlopen, and invokes
  // noleax_agent_attach_bootstrap(parameters) inside it. Restores every thread's
  // original state and detaches on all paths. Throws ControllerError on failure
  // (message must say why; system_error carries errno where applicable).
  static void inject(std::uint32_t process_id, const std::filesystem::path& agent_path,
                     const std::vector<std::byte>& bootstrap_parameters);
};

}  // namespace noleax::controller::linux
