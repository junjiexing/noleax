#pragma once

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <memory>

#include "noleax/agent/windows/bootstrap.hpp"
#include "noleax/controller/windows/remote_injector.hpp"

namespace noleax::controller::windows {

// Thread-hijack injection (P7A).
//
// A thread of the target process is suspended, its full CONTEXT (control,
// integer, segments and floating point/XMM state) is captured, and its RIP is
// redirected to a bootstrap stub that loads the agent with LdrLoadDll and
// invokes noleax_agent_bootstrap. The stub deliberately clobbers registers;
// once it signals completion the controller suspends the thread again and
// restores the saved context, so the thread resumes exactly where it was
// interrupted. Because the final restore is a SetThreadContext kernel
// transition instead of a hand-written indirect jump, the flow stays valid
// for CET/IBT and shadow-stack enforced targets.
//
// The hijack is split into explicit phases so the controller can perform the
// IPC handshake while the bootstrap stub waits for capture readiness:
//
//   1. prepare (constructor): resolves addresses, picks a thread (or uses the
//      supplied suspended main thread), saves its context and redirects RIP.
//   2. start(): resumes the thread so it executes the stub.
//   3. finish(): waits for the stub, validates the result, restores the saved
//      context and releases remote memory. The thread is always restored,
//      even when the stub reports an error or the wait times out.
//
// abort() restores the thread when the session is abandoned between start()
// and finish() (for example when the agent handshake fails).
class ThreadHijack final {
 public:
  struct Options {
    // When set, this already-suspended thread (a launch main thread) is
    // hijacked. When null, a running thread of the process is selected and
    // suspended automatically (attach).
    void* thread_handle{nullptr};
    // When true the stub waits until noleax_agent_capture_is_ready reports a
    // ready capture before signalling completion, keeping the hijacked thread
    // parked until the controller finished the StartCapture handshake.
    bool wait_for_ready{true};
  };

  ThreadHijack(void* process_handle, std::uint32_t process_id,
               const std::filesystem::path& agent_path,
               const noleax::agent::windows::BootstrapParameters& bootstrap,
               const Options& options);
  ~ThreadHijack();

  ThreadHijack(const ThreadHijack&) = delete;
  ThreadHijack& operator=(const ThreadHijack&) = delete;

  void start();
  [[nodiscard]] std::uintptr_t finish(std::chrono::milliseconds timeout);
  void abort() noexcept;

  [[nodiscard]] std::uint32_t thread_id() const noexcept;

 private:
  class Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace noleax::controller::windows
