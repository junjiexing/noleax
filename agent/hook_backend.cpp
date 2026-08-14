#include "noleax/agent/hook_backend.hpp"

#include <hoox.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <limits>
#include <memory>
#include <mutex>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace noleax::agent {
namespace {

std::mutex transaction_mutex;

[[nodiscard]] HookInstallStatus map_install_status(HooxReplaceReturn status) noexcept {
  switch (status) {
    case HOOX_REPLACE_OK:
      return HookInstallStatus::kInstalled;
    case HOOX_REPLACE_WRONG_SIGNATURE:
      return HookInstallStatus::kWrongSignature;
    case HOOX_REPLACE_ALREADY_REPLACED:
      return HookInstallStatus::kAlreadyReplaced;
    case HOOX_REPLACE_POLICY_VIOLATION:
      return HookInstallStatus::kPolicyViolation;
    case HOOX_REPLACE_WRONG_TYPE:
      return HookInstallStatus::kWrongType;
  }
  return HookInstallStatus::kWrongType;
}

}  // namespace

class HookBackend::Impl {
 public:
  Impl() {
    hoox_init();
    interceptor_ = hoox_interceptor_obtain();
    if (interceptor_ == nullptr) {
      hoox_deinit();
      throw HookBackendError{"Hoox did not provide an interceptor"};
    }
  }

  ~Impl() {
    std::scoped_lock lock{mutex_};
    if (interceptor_ != nullptr && !shutdown_locked(quiescence_deadline_after())) {
      // Revert has already stopped new calls. Retain the Hoox references instead of freeing a
      // trampoline covered by a replacement lease or instrumentation still being executed.
      interceptor_ = nullptr;
    }
  }

  [[nodiscard]] FastHookResult install_fast(void* target, void* replacement,
                                            OriginalTrampolineSlot* original_slot) {
    return install_with_policy(target, replacement, original_slot, HOOX_RELOCATION_CHECKED);
  }

  [[nodiscard]] FastHookResult install_fast_forced(void* target, void* replacement,
                                                   OriginalTrampolineSlot* original_slot) {
    return install_with_policy(target, replacement, original_slot, HOOX_RELOCATION_FORCED);
  }

  [[nodiscard]] FastHookResult install_with_policy(void* target, void* replacement,
                                                   OriginalTrampolineSlot* original_slot,
                                                   HooxRelocationPolicy relocation_policy) {
    std::scoped_lock lock{mutex_};
    if (interceptor_ == nullptr || stopping_) {
      return {HookInstallStatus::kBackendStopped, nullptr};
    }
    if (pending_teardown_) {
      return {HookInstallStatus::kTeardownPending, nullptr};
    }
    if (target == nullptr || replacement == nullptr || target == replacement) {
      return {HookInstallStatus::kInvalidArgument, nullptr};
    }

    const auto existing = find_entry(target);
    if (existing != entries_.end()) {
      if (original_slot != nullptr) {
        original_slot->store(existing->original, std::memory_order_release);
      }
      return {HookInstallStatus::kAlreadyInstalled, existing->original};
    }

    // Keep activation deferred until both backend bookkeeping and any caller-provided original
    // slot are ready. This is required when the target allocator can be reached by bookkeeping
    // performed after Hoox has created the trampoline.
    std::scoped_lock transaction_lock{transaction_mutex};
    hoox_interceptor_begin_transaction(interceptor_);
    HooxInterceptorOptions options{};
    options.scenario = HOOX_INTERCEPTOR_SCENARIO_ONLINE;
    options.relocation_policy = relocation_policy;
    void* original = nullptr;
    const HooxReplaceReturn replace_status =
        hoox_interceptor_replace_fast(interceptor_, target, replacement, &original, &options);
    const HookInstallStatus status = map_install_status(replace_status);
    if (status != HookInstallStatus::kInstalled) {
      hoox_interceptor_end_transaction(interceptor_);
      return {status, nullptr};
    }
    if (original == nullptr) {
      hoox_interceptor_revert(interceptor_, target);
      pending_teardown_ = true;
      hoox_interceptor_end_transaction(interceptor_);
      static_cast<void>(flush_locked(quiescence_deadline_after()));
      return {HookInstallStatus::kMissingOriginal, nullptr};
    }

    try {
      entries_.push_back(Entry{target, replacement, original});
    } catch (...) {
      hoox_interceptor_revert(interceptor_, target);
      pending_teardown_ = true;
      hoox_interceptor_end_transaction(interceptor_);
      static_cast<void>(flush_locked(quiescence_deadline_after()));
      throw;
    }

    if (original_slot != nullptr) {
      original_slot->store(original, std::memory_order_release);
    }
    hoox_interceptor_end_transaction(interceptor_);
    return {HookInstallStatus::kInstalled, original};
  }

  [[nodiscard]] HookUninstallStatus uninstall(void* target, QuiescenceDeadline deadline) noexcept {
    std::scoped_lock lock{mutex_};
    if (interceptor_ == nullptr || stopping_) {
      return HookUninstallStatus::kBackendStopped;
    }
    const auto entry = find_entry(target);
    if (entry == entries_.end()) {
      return HookUninstallStatus::kNotInstalled;
    }

    hoox_interceptor_revert(interceptor_, target);
    entries_.erase(entry);
    pending_teardown_ = true;
    return flush_locked(deadline) ? HookUninstallStatus::kUninstalled
                                  : HookUninstallStatus::kTeardownPending;
  }

  [[nodiscard]] bool flush(QuiescenceDeadline deadline) noexcept {
    std::scoped_lock lock{mutex_};
    return flush_locked(deadline);
  }

  [[nodiscard]] bool shutdown(QuiescenceDeadline deadline) noexcept {
    std::scoped_lock lock{mutex_};
    return shutdown_locked(deadline);
  }

  [[nodiscard]] bool acquire_trampoline_lifetime_lease() noexcept {
    std::scoped_lock lock{mutex_};
    if (interceptor_ == nullptr || stopping_ ||
        trampoline_lifetime_leases_ == std::numeric_limits<std::size_t>::max()) {
      return false;
    }
    ++trampoline_lifetime_leases_;
    return true;
  }

  void release_trampoline_lifetime_lease() noexcept {
    std::scoped_lock lock{mutex_};
    if (trampoline_lifetime_leases_ == 0U) {
      std::terminate();
    }
    --trampoline_lifetime_leases_;
  }

  [[nodiscard]] bool is_active() const noexcept {
    std::scoped_lock lock{mutex_};
    return interceptor_ != nullptr && !stopping_;
  }

  [[nodiscard]] bool has_pending_teardown() const noexcept {
    std::scoped_lock lock{mutex_};
    return pending_teardown_;
  }

  [[nodiscard]] std::size_t installed_count() const noexcept {
    std::scoped_lock lock{mutex_};
    return entries_.size();
  }

  [[nodiscard]] std::size_t trampoline_lifetime_lease_count() const noexcept {
    std::scoped_lock lock{mutex_};
    return trampoline_lifetime_leases_;
  }

 private:
  struct Entry {
    void* target;
    void* replacement;
    void* original;
  };

  using EntryIterator = std::vector<Entry>::iterator;

  [[nodiscard]] EntryIterator find_entry(void* target) noexcept {
    return std::find_if(entries_.begin(), entries_.end(),
                        [target](const Entry& entry) { return entry.target == target; });
  }

  // Retries the Hoox flush until the deadline, yielding between attempts. The yield (not a
  // millisecond sleep) keeps per-attempt pacing at microsecond scale: a flush under
  // contention can need hundreds of rounds, and 1 ms each balloons the finalize path past
  // the controller's pipe timeout (the Windows capture-lifecycle hang). The deadline
  // bounds the total; an already-expired deadline makes no attempt: callers spell the old
  // "revert only, flush later" zero-attempt form as steady_clock::now().
  [[nodiscard]] bool flush_locked(QuiescenceDeadline deadline) noexcept {
    if (interceptor_ == nullptr) {
      return true;
    }
    if (trampoline_lifetime_leases_ != 0U) {
      return false;
    }
    while (std::chrono::steady_clock::now() < deadline) {
      if (hoox_interceptor_flush(interceptor_) != 0) {
        pending_teardown_ = false;
        return true;
      }
      std::this_thread::yield();
    }
    return false;
  }

  [[nodiscard]] bool shutdown_locked(QuiescenceDeadline deadline) noexcept {
    if (interceptor_ == nullptr) {
      return true;
    }
    stopping_ = true;
    if (!entries_.empty()) {
      std::scoped_lock transaction_lock{transaction_mutex};
      hoox_interceptor_begin_transaction(interceptor_);
      for (const Entry& entry : entries_) {
        hoox_interceptor_revert(interceptor_, entry.target);
      }
      hoox_interceptor_end_transaction(interceptor_);
      entries_.clear();
      pending_teardown_ = true;
    }
    if (!flush_locked(deadline)) {
      return false;
    }

    HooxInterceptor* const interceptor = std::exchange(interceptor_, nullptr);
    hoox_interceptor_unref(interceptor);
    hoox_deinit();
    return true;
  }

  mutable std::mutex mutex_;
  HooxInterceptor* interceptor_{nullptr};
  std::vector<Entry> entries_;
  std::size_t trampoline_lifetime_leases_{0U};
  bool pending_teardown_{false};
  bool stopping_{false};
};

std::string_view hook_install_status_name(HookInstallStatus status) noexcept {
  switch (status) {
    case HookInstallStatus::kInstalled:
      return "installed";
    case HookInstallStatus::kInvalidArgument:
      return "invalid_argument";
    case HookInstallStatus::kAlreadyInstalled:
      return "already_installed";
    case HookInstallStatus::kAlreadyReplaced:
      return "already_replaced";
    case HookInstallStatus::kWrongSignature:
      return "wrong_signature";
    case HookInstallStatus::kPolicyViolation:
      return "policy_violation";
    case HookInstallStatus::kWrongType:
      return "wrong_type";
    case HookInstallStatus::kMissingOriginal:
      return "missing_original";
    case HookInstallStatus::kTeardownPending:
      return "teardown_pending";
    case HookInstallStatus::kBackendStopped:
      return "backend_stopped";
  }
  return "unknown";
}

std::string_view hook_uninstall_status_name(HookUninstallStatus status) noexcept {
  switch (status) {
    case HookUninstallStatus::kUninstalled:
      return "uninstalled";
    case HookUninstallStatus::kNotInstalled:
      return "not_installed";
    case HookUninstallStatus::kTeardownPending:
      return "teardown_pending";
    case HookUninstallStatus::kBackendStopped:
      return "backend_stopped";
  }
  return "unknown";
}

HookBackend::HookBackend() : impl_{std::make_unique<Impl>()} {}

HookBackend::~HookBackend() = default;

void HookBackend::set_external_thread_suspension(bool enabled) noexcept {
  hoox_memory_set_external_thread_suspension(enabled ? 1 : 0);
}

FastHookResult HookBackend::install_fast(void* target, void* replacement,
                                         OriginalTrampolineSlot* original_slot) {
  return impl_->install_fast(target, replacement, original_slot);
}

FastHookResult HookBackend::install_fast_forced(void* target, void* replacement,
                                                OriginalTrampolineSlot* original_slot) {
  return impl_->install_fast_forced(target, replacement, original_slot);
}

HookUninstallStatus HookBackend::uninstall(void* target, QuiescenceDeadline deadline) noexcept {
  return impl_->uninstall(target, deadline);
}

bool HookBackend::flush(QuiescenceDeadline deadline) noexcept { return impl_->flush(deadline); }

bool HookBackend::shutdown(QuiescenceDeadline deadline) noexcept {
  return impl_->shutdown(deadline);
}

bool HookBackend::acquire_trampoline_lifetime_lease() noexcept {
  return impl_->acquire_trampoline_lifetime_lease();
}

void HookBackend::release_trampoline_lifetime_lease() noexcept {
  impl_->release_trampoline_lifetime_lease();
}

bool HookBackend::is_active() const noexcept { return impl_->is_active(); }

bool HookBackend::has_pending_teardown() const noexcept { return impl_->has_pending_teardown(); }

std::size_t HookBackend::installed_count() const noexcept { return impl_->installed_count(); }

std::size_t HookBackend::trampoline_lifetime_lease_count() const noexcept {
  return impl_->trampoline_lifetime_lease_count();
}

}  // namespace noleax::agent
