#include <cstdint>

#include "noleax/agent/hook_backend.hpp"
#include "noleax/agent/windows/rtl_allocate_heap_hook.hpp"

#define NOLEAX_HOOK_HARNESS_EXPORT extern "C" __declspec(dllexport)

namespace {

noleax::agent::HookBackend* backend = nullptr;
noleax::agent::windows::RtlAllocateHeapHook* hook = nullptr;

void destroy_harness() noexcept {
  delete hook;
  hook = nullptr;
  delete backend;
  backend = nullptr;
}

}  // namespace

NOLEAX_HOOK_HARNESS_EXPORT std::uint32_t noleax_test_rtl_allocate_heap_hook_abi_version() noexcept {
  return 1U;
}

NOLEAX_HOOK_HARNESS_EXPORT std::uint32_t noleax_test_rtl_allocate_heap_hook_install() noexcept {
  if (hook != nullptr) {
    return 1U;
  }

  try {
    backend = new noleax::agent::HookBackend{};
    hook = new noleax::agent::windows::RtlAllocateHeapHook{*backend};
    const auto result = hook->install();
    if (!result.installed()) {
      const auto status = static_cast<std::uint32_t>(result.status);
      destroy_harness();
      return 100U + status;
    }
  } catch (...) {
    destroy_harness();
    return 0xffffffffU;
  }
  return 0U;
}

NOLEAX_HOOK_HARNESS_EXPORT std::uint64_t noleax_test_rtl_allocate_heap_hook_call_count() noexcept {
  return hook != nullptr ? hook->call_count() : 0U;
}

NOLEAX_HOOK_HARNESS_EXPORT std::uint32_t noleax_test_rtl_allocate_heap_hook_stop() noexcept {
  if (hook == nullptr || backend == nullptr) {
    return 1U;
  }

  auto uninstall_status = hook->uninstall();
  if (uninstall_status == noleax::agent::HookUninstallStatus::kTeardownPending && hook->flush()) {
    uninstall_status = noleax::agent::HookUninstallStatus::kUninstalled;
  }
  if (uninstall_status != noleax::agent::HookUninstallStatus::kUninstalled) {
    return 2U;
  }
  if (!backend->shutdown()) {
    return 3U;
  }

  destroy_harness();
  return 0U;
}
