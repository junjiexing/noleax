#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <vector>

#include "noleax/ipc/protocol.hpp"

namespace noleax::controller::linux {

// Ptrace attach injector (docs/LINUX_PORT_PLAN.md §M6, docs/LINUX_PTRACE_INJECTION.md):
// seizes a RUNNING process with PTRACE_SEIZE, hijacks one safely-parked thread, and uses
// it to dlopen the agent image and call its attach bootstrap export. Since H1-B the
// bootstrap runs synchronously on the hijacked thread, so the whole process stays
// stopped through the handshake and hook installation — no business thread can execute a
// partially written prologue. The thread-selection rules (never a thread parked inside
// ld.so, prefer a thread blocked in a syscall) follow the thread-hijack lessons of
// docs/THREAD_HIJACK_INJECTION.md; every wait is bounded by the configured timeout and
// any ordinary failure restores the original state before the error propagates, so the
// target is never left seized. The one exception is a wedged bootstrap (outlived the
// timeout plus one grace budget while still inside the injected call): restoring the
// pre-hijack registers there would teleport a thread out of mid-agent code, so the
// injector restores nothing, leaves the process stopped under the seizure, and fails
// loudly instead.
//
// One RWX stub page (4 KiB) is deliberately left mapped inside the target: it holds the
// call stub, the agent path string, and the bootstrap parameter blob. Unmapping it would
// require running a final munmap stub whose own int3 lives on the page being unmapped;
// the page stays, documented, exactly like the loaded agent image itself.
class PtraceInjector final {
 public:
  // Seizes the target process, injects agent_path via dlopen, and invokes
  // noleax_agent_attach_bootstrap(parameters) inside it. The bootstrap stays inside the
  // stop window through hook installation; the injector returns only after the agent
  // signaled install-complete. Restores every thread's original state and detaches on
  // all ordinary paths. Throws ControllerError on failure (message must say why;
  // system_error carries errno where applicable). `timeout` covers the whole sequence —
  // seizure, dlopen, bootstrap, handshake, install — and one extra timeout-sized grace
  // budget is granted to an in-flight stub call before it is declared wedged.
  // `custom_hooks` declares the capture's custom hook points: their resolved addresses
  // join the built-in patch windows the seizure sweeps threads out of before any patch.
  static void inject(std::uint32_t process_id, const std::filesystem::path& agent_path,
                     const std::vector<std::byte>& bootstrap_parameters,
                     std::chrono::milliseconds timeout = std::chrono::seconds{10},
                     const std::vector<noleax::ipc::CustomHookSpec>& custom_hooks = {});
};

}  // namespace noleax::controller::linux
