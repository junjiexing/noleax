#pragma once

#include <cstdint>

namespace noleax::agent {

struct HookCodeRegion {
  const void* begin{nullptr};
  const void* end{nullptr};
};

// Default per-call attempt budget for the rendezvous. Teardown is retried by the flush driver,
// so a single call stays cheap and leaves scheduling headroom instead of spinning for long.
inline constexpr std::uint32_t kDefaultRendezvousMaxAttempts = 50U;

// Returns the ".nlxhk" section of the module that contains the given address. That section holds
// the replacement entry points and their uncounted lifecycle window. Returns an empty region
// when the address belongs to no loaded module or the module has no such section.
[[nodiscard]] HookCodeRegion hook_code_region(const void* address_in_module) noexcept;

// Suspends every peer thread and verifies that no thread instruction pointer falls inside the
// region, retrying a bounded number of times. Fails closed: an empty region, any thread that
// cannot be opened, suspended or read, and any thread still inside the region all report false.
// The caller must hold no locks; this function performs no heap allocation and touches no loader
// state while peer threads are suspended.
[[nodiscard]] bool verify_replacement_evacuated(HookCodeRegion region,
                                                std::uint32_t max_attempts) noexcept;

}  // namespace noleax::agent
