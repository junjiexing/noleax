#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstdint>
#include <iostream>

namespace {

using AgentAbiVersion = std::uint32_t (*)() noexcept;
using VerifyHookBackendLinkage = bool (*)() noexcept;

}  // namespace

int wmain(int argc, wchar_t* argv[]) {
  if (argc != 2) {
    std::cerr << "expected the agent DLL path\n";
    return 1;
  }

  const HMODULE agent = LoadLibraryW(argv[1]);
  if (agent == nullptr) {
    std::cerr << "LoadLibraryW failed: " << GetLastError() << '\n';
    return 2;
  }

  const auto abi_version =
      reinterpret_cast<AgentAbiVersion>(GetProcAddress(agent, "noleax_agent_abi_version"));
  const auto verify_backend = reinterpret_cast<VerifyHookBackendLinkage>(
      GetProcAddress(agent, "noleax_agent_verify_hook_backend_linkage"));

  int result = 0;
  if (abi_version == nullptr || abi_version() != 1U) {
    std::cerr << "agent ABI export is missing or incompatible\n";
    result = 3;
  } else if (verify_backend == nullptr || !verify_backend()) {
    std::cerr << "Hoox linkage verification failed\n";
    result = 4;
  }

  if (!FreeLibrary(agent) && result == 0) {
    std::cerr << "FreeLibrary failed: " << GetLastError() << '\n';
    result = 5;
  }

  return result;
}
