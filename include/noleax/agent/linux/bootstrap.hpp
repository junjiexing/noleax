#pragma once

#include <array>
#include <cstdint>
#include <type_traits>

namespace noleax::agent::linux {

// Environment-channel bootstrap contract for LD_PRELOAD launch (docs/LINUX_PORT_PLAN.md
// §5.1). The controller sets these before exec; the agent reads and then unsets them in
// its constructor so they never leak into the target's own children.
//
// Controller session mode:
//   NOLEAX_BOOTSTRAP_SOCKET     abstract unix socket name without the leading NUL
//   NOLEAX_SESSION_TOKEN        16-byte session token as 32 lowercase hex chars
//   NOLEAX_CONTROLLER_PID       controller process id (peer verification)
//   NOLEAX_CONNECT_TIMEOUT_MS   bootstrap connect timeout (default 10000)
//
// Standalone mode (no controller): NOLEAX_AGENT_CONFIG points at the capture TOML;
// mirrors the Windows standalone sidecar semantics.
inline constexpr char kBootstrapSocketEnv[] = "NOLEAX_BOOTSTRAP_SOCKET";
inline constexpr char kSessionTokenEnv[] = "NOLEAX_SESSION_TOKEN";
inline constexpr char kControllerPidEnv[] = "NOLEAX_CONTROLLER_PID";
inline constexpr char kConnectTimeoutEnv[] = "NOLEAX_CONNECT_TIMEOUT_MS";
inline constexpr char kAgentConfigEnv[] = "NOLEAX_AGENT_CONFIG";
// Test seam (H1-A, docs/HARDENING_PLAN.md): shrinks the capture-stop drain quiescence
// budget (milliseconds, 1..3600000) so tests can force a bounded drain timeout against a
// slow in-flight replacement call. Scrubbed with the rest of the channel.
inline constexpr char kDrainBudgetEnv[] = "NOLEAX_DRAIN_BUDGET_MS";

inline constexpr std::uint32_t kDefaultConnectTimeoutMs = 10'000U;

// Attach bootstrap ABI (port M6): there is no env channel when attaching to a running
// process, so the ptrace injector calls this export after dlopening the agent, passing
// the same session fields the env channel would carry.
inline constexpr std::uint32_t kAttachBootstrapVersion = 1U;
inline constexpr std::size_t kAttachSocketNameCapacity = 64U;

struct AttachBootstrapParameters {
  std::uint32_t structure_size{sizeof(AttachBootstrapParameters)};
  std::uint32_t version{kAttachBootstrapVersion};
  std::uint32_t controller_process_id{0U};
  std::uint32_t connect_timeout_ms{kDefaultConnectTimeoutMs};
  // Abstract unix socket name without the leading NUL (the env channel spelling).
  char socket_name[kAttachSocketNameCapacity]{};
  std::array<std::byte, 16U> session_token{};
};

static_assert(std::is_trivially_copyable_v<AttachBootstrapParameters>);

// Returns 0 on success; the session worker runs the handshake from there.
extern "C" std::uint32_t noleax_agent_attach_bootstrap(
    const AttachBootstrapParameters* parameters) noexcept;

}  // namespace noleax::agent::linux
