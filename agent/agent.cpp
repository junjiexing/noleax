#include <hoox.h>

#include <cstdint>

#include "noleax/version.hpp"

#if defined(_WIN32)
#define NOLEAX_AGENT_EXPORT extern "C" __declspec(dllexport)
#else
#define NOLEAX_AGENT_EXPORT extern "C" __attribute__((visibility("default")))
#endif

NOLEAX_AGENT_EXPORT std::uint32_t noleax_agent_abi_version() noexcept {
  return noleax::kAgentAbiVersion;
}

NOLEAX_AGENT_EXPORT bool noleax_agent_verify_hook_backend_linkage() noexcept {
  hoox_init();
  hoox_deinit();
  return true;
}
