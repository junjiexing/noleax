#include "noleax/agent/linux/module_tracker.hpp"

#include <link.h>

#include <algorithm>
#include <cstring>
#include <string>
#include <utility>

namespace noleax::agent::linux {
namespace {

struct ModuleIdentity {
  std::uint64_t base{0U};
  std::uint64_t size{0U};
  std::string path;
};

// Bounds the module's mapped image as [base, base+size): the span of its PT_LOAD
// segments relative to the load bias. The main executable arrives with an empty name
// and is reported through /proc/self/exe.
[[nodiscard]] bool describe_module(const dl_phdr_info& info, ModuleIdentity& module) {
  std::uint64_t lowest = UINT64_MAX;
  std::uint64_t highest = 0U;
  for (int index = 0; index < info.dlpi_phnum; ++index) {
    const Elf64_Phdr& header = info.dlpi_phdr[index];
    if (header.p_type != PT_LOAD) {
      continue;
    }
    lowest = std::min(lowest, static_cast<std::uint64_t>(header.p_vaddr));
    highest = std::max(highest, static_cast<std::uint64_t>(header.p_vaddr + header.p_memsz));
  }
  if (lowest == UINT64_MAX || highest <= lowest) {
    return false;
  }
  module.base = static_cast<std::uint64_t>(info.dlpi_addr) + lowest;
  module.size = highest - lowest;
  if (info.dlpi_name != nullptr && info.dlpi_name[0] != '\0') {
    module.path = info.dlpi_name;
  } else {
    module.path = "/proc/self/exe";
  }
  return true;
}

struct SnapshotContext {
  std::vector<ModuleIdentity>* modules;
};

int snapshot_callback(dl_phdr_info* info, std::size_t /*size*/, void* data) {
  auto* const context = static_cast<SnapshotContext*>(data);
  ModuleIdentity module;
  if (describe_module(*info, module)) {
    context->modules->push_back(std::move(module));
  }
  return 0;
}

[[nodiscard]] std::vector<ModuleIdentity> take_snapshot() {
  std::vector<ModuleIdentity> modules;
  SnapshotContext context{&modules};
  dl_iterate_phdr(&snapshot_callback, &context);
  std::sort(modules.begin(), modules.end(),
            [](const ModuleIdentity& left, const ModuleIdentity& right) {
              return left.base < right.base;
            });
  return modules;
}

[[nodiscard]] RawModuleEvent make_event(const ModuleIdentity& module, RawModuleEventType type,
                                        std::uint64_t ticks, std::uint32_t flags) noexcept {
  RawModuleEvent event;
  event.monotonic_ticks = ticks;
  event.base_address = module.base;
  event.image_size = module.size;
  event.type = type;
  event.flags = flags;
  const std::size_t length = std::min(module.path.size(), kMaximumRawModulePathBytes - 1U);
  if (length < module.path.size()) {
    event.flags |= static_cast<std::uint32_t>(RawModuleEventFlag::kPathTruncated);
  }
  std::memcpy(event.path.data(), module.path.data(), length);
  event.path_length = static_cast<std::uint16_t>(length);
  return event;
}

[[nodiscard]] std::uint64_t monotonic_now_ns() noexcept {
  timespec value{};
  clock_gettime(CLOCK_MONOTONIC, &value);
  return static_cast<std::uint64_t>(value.tv_sec) * 1'000'000'000ULL +
         static_cast<std::uint64_t>(value.tv_nsec);
}

}  // namespace

class LinuxModuleTracker::Implementation {
 public:
  explicit Implementation(std::uint64_t monotonic_origin, std::size_t queue_capacity)
      : monotonic_origin_{monotonic_origin},
        queue_capacity_{queue_capacity},
        pending_{std::make_unique<RawModuleEvent[]>(queue_capacity)} {
    live_ = take_snapshot();
    initial_.reserve(live_.size());
    for (const ModuleIdentity& module : live_) {
      initial_.push_back(
          make_event(module, RawModuleEventType::kLoad, monotonic_origin_,
                     static_cast<std::uint32_t>(RawModuleEventFlag::kInitialSnapshot)));
    }
  }

  [[nodiscard]] std::span<const RawModuleEvent> initial_modules() const noexcept {
    return initial_;
  }

  void poll() noexcept {
    try {
      poll_impl();
    } catch (...) {
      // Allocation pressure must not kill the capture; skip this round and account it.
      ++dropped_;
    }
  }

  void poll_impl() {
    const std::vector<ModuleIdentity> current = take_snapshot();
    // Bases are unique among live modules at any instant; a base that disappears and
    // reappears with different content reads as unload+load, matching the generation
    // semantics the writer maintains for address reuse.
    for (const ModuleIdentity& live_module : live_) {
      const auto found = std::lower_bound(
          current.begin(), current.end(), live_module.base,
          [](const ModuleIdentity& module, std::uint64_t base) { return module.base < base; });
      if (found == current.end() || found->base != live_module.base) {
        enqueue(make_event(live_module, RawModuleEventType::kUnload, monotonic_now_ns(), 0U));
      }
    }
    for (const ModuleIdentity& module : current) {
      const auto found = std::lower_bound(
          live_.begin(), live_.end(), module.base,
          [](const ModuleIdentity& module, std::uint64_t base) { return module.base < base; });
      if (found == live_.end() || found->base != module.base) {
        enqueue(make_event(module, RawModuleEventType::kLoad, monotonic_now_ns(), 0U));
      } else if (found->size != module.size || found->path != module.path) {
        // Same base, different content: treat as unload+load of the generation.
        enqueue(make_event(*found, RawModuleEventType::kUnload, monotonic_now_ns(), 0U));
        enqueue(make_event(module, RawModuleEventType::kLoad, monotonic_now_ns(), 0U));
      }
    }
    live_ = current;
  }

  [[nodiscard]] bool try_dequeue(RawModuleEvent& event) noexcept {
    if (pending_count_ == 0U) {
      return false;
    }
    event = pending_[pending_head_];
    pending_head_ = (pending_head_ + 1U) % queue_capacity_;
    --pending_count_;
    return true;
  }

  [[nodiscard]] std::uint64_t take_dropped_event_count() noexcept {
    return std::exchange(dropped_, 0U);
  }

  [[nodiscard]] std::size_t queue_capacity() const noexcept { return queue_capacity_; }

  [[nodiscard]] std::size_t live_module_count() const noexcept { return live_.size(); }

 private:
  void enqueue(const RawModuleEvent& event) noexcept {
    if (pending_count_ == queue_capacity_) {
      ++dropped_;
      return;
    }
    pending_[(pending_head_ + pending_count_) % queue_capacity_] = event;
    ++pending_count_;
  }

  const std::uint64_t monotonic_origin_;
  const std::size_t queue_capacity_;
  std::vector<ModuleIdentity> live_;
  std::vector<RawModuleEvent> initial_;
  std::unique_ptr<RawModuleEvent[]> pending_;
  std::size_t pending_head_{0U};
  std::size_t pending_count_{0U};
  std::uint64_t dropped_{0U};
};

LinuxModuleTracker::LinuxModuleTracker(std::uint64_t monotonic_origin, std::size_t queue_capacity)
    : implementation_{std::make_unique<Implementation>(
          monotonic_origin, (std::max)(queue_capacity, std::size_t{1U}))} {}

LinuxModuleTracker::~LinuxModuleTracker() = default;

std::span<const RawModuleEvent> LinuxModuleTracker::initial_modules() const noexcept {
  return implementation_->initial_modules();
}

void LinuxModuleTracker::poll() noexcept { implementation_->poll(); }

bool LinuxModuleTracker::try_dequeue(RawModuleEvent& event) noexcept {
  return implementation_->try_dequeue(event);
}

std::uint64_t LinuxModuleTracker::take_dropped_event_count() noexcept {
  return implementation_->take_dropped_event_count();
}

std::size_t LinuxModuleTracker::queue_capacity() const noexcept {
  return implementation_->queue_capacity();
}

std::size_t LinuxModuleTracker::live_module_count() const noexcept {
  return implementation_->live_module_count();
}

}  // namespace noleax::agent::linux
