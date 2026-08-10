#pragma once

#include <cstdint>

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

inline constexpr std::uint32_t kDefaultConnectTimeoutMs = 10'000U;

}  // namespace noleax::agent::linux
