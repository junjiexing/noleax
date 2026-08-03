#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <cstdint>
#include <cstdlib>
#include <iterator>

// Test double for the agent DLL: noleax_agent_bootstrap sleeps a configurable
// delay (NOLEAX_SLOW_BOOTSTRAP_MS, inherited from the spawning test process) so
// thread-hijack tests can park the bootstrap stub at a controlled stage.
extern "C" {

__declspec(dllexport) std::uint32_t NTAPI noleax_agent_bootstrap(void* /*params*/) {
  wchar_t buffer[16]{};
  const DWORD length = GetEnvironmentVariableW(L"NOLEAX_SLOW_BOOTSTRAP_MS", buffer,
                                               static_cast<DWORD>(std::size(buffer)));
  const unsigned long delay = length != 0U ? wcstoul(buffer, nullptr, 10) : 500U;
  Sleep(delay != 0U ? static_cast<DWORD>(delay) : 500U);
  return 0U;
}

__declspec(dllexport) bool NTAPI noleax_agent_capture_is_ready() { return true; }

}  // extern "C"
