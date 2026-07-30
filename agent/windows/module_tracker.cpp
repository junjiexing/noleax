#include "noleax/agent/windows/module_tracker.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
// clang-format off: psapi.h requires the Windows base types.
#include <windows.h>
#include <psapi.h>
// clang-format on
#include <winternl.h>

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "noleax/agent/bounded_mpsc_queue.hpp"
#include "noleax/agent/hook_guard.hpp"

namespace noleax::agent::windows {
namespace {

constexpr ULONG kDllNotificationReasonLoaded = 1U;
constexpr ULONG kDllNotificationReasonUnloaded = 2U;
constexpr DWORD kCodeViewRsdsSignature = 0x53445352U;
constexpr std::size_t kMaximumDebugDirectoryEntries = 64U;

struct DllLoadedNotificationData {
  ULONG flags;
  PCUNICODE_STRING full_dll_name;
  PCUNICODE_STRING base_dll_name;
  PVOID dll_base;
  ULONG size_of_image;
};

struct DllUnloadedNotificationData {
  ULONG flags;
  PCUNICODE_STRING full_dll_name;
  PCUNICODE_STRING base_dll_name;
  PVOID dll_base;
  ULONG size_of_image;
};

union DllNotificationData {
  DllLoadedNotificationData loaded;
  DllUnloadedNotificationData unloaded;
};

using DllNotificationCallback = void(CALLBACK*)(ULONG reason, const DllNotificationData* data,
                                                void* context);
using RegisterDllNotification = NTSTATUS(NTAPI*)(ULONG flags, DllNotificationCallback callback,
                                                 void* context, void** cookie);
using UnregisterDllNotification = NTSTATUS(NTAPI*)(void* cookie);

[[nodiscard]] bool nt_success(NTSTATUS status) noexcept { return status >= 0; }

[[nodiscard]] std::uint32_t flag_value(RawModuleEventFlag flag) noexcept {
  return static_cast<std::uint32_t>(flag);
}

void set_flag(RawModuleEvent& event, RawModuleEventFlag flag) noexcept {
  event.flags |= flag_value(flag);
}

[[nodiscard]] std::uint64_t query_ticks(std::uint64_t fallback) noexcept {
  LARGE_INTEGER counter{};
  if (QueryPerformanceCounter(&counter) == FALSE || counter.QuadPart < 0) {
    return fallback;
  }
  return static_cast<std::uint64_t>(counter.QuadPart);
}

[[nodiscard]] bool checked_address(std::uint64_t base, std::uint64_t offset,
                                   const void*& address) noexcept {
  if (offset > std::numeric_limits<std::uint64_t>::max() - base) {
    return false;
  }
  address = std::bit_cast<const void*>(static_cast<std::uintptr_t>(base + offset));
  return true;
}

template <typename T>
[[nodiscard]] bool read_process_value(std::uint64_t base, std::uint64_t offset, T& value) noexcept {
  const void* address = nullptr;
  if (!checked_address(base, offset, address)) {
    return false;
  }
  SIZE_T bytes_read = 0U;
  return ReadProcessMemory(GetCurrentProcess(), address, &value, sizeof(value), &bytes_read) !=
             FALSE &&
         bytes_read == sizeof(value);
}

[[nodiscard]] bool read_process_bytes(std::uint64_t base, std::uint64_t offset, void* destination,
                                      std::size_t size) noexcept {
  const void* address = nullptr;
  if (!checked_address(base, offset, address)) {
    return false;
  }
  SIZE_T bytes_read = 0U;
  return ReadProcessMemory(GetCurrentProcess(), address, destination, size, &bytes_read) != FALSE &&
         bytes_read == size;
}

void capture_code_view(RawModuleEvent& event,
                       const IMAGE_DATA_DIRECTORY& debug_directory) noexcept {
  if (debug_directory.VirtualAddress == 0U ||
      debug_directory.Size < sizeof(IMAGE_DEBUG_DIRECTORY)) {
    return;
  }
  const std::size_t count =
      (std::min)(static_cast<std::size_t>(debug_directory.Size) / sizeof(IMAGE_DEBUG_DIRECTORY),
                 kMaximumDebugDirectoryEntries);
  for (std::size_t index = 0U; index < count; ++index) {
    IMAGE_DEBUG_DIRECTORY entry{};
    const std::uint64_t offset = static_cast<std::uint64_t>(debug_directory.VirtualAddress) +
                                 index * sizeof(IMAGE_DEBUG_DIRECTORY);
    if (!read_process_value(event.base_address, offset, entry) ||
        entry.Type != IMAGE_DEBUG_TYPE_CODEVIEW || entry.AddressOfRawData == 0U ||
        entry.SizeOfData < 24U) {
      continue;
    }

    std::array<std::byte, 24> header{};
    if (!read_process_bytes(event.base_address, entry.AddressOfRawData, header.data(),
                            header.size())) {
      continue;
    }
    std::uint32_t signature = 0U;
    std::memcpy(&signature, header.data(), sizeof(signature));
    if (signature != kCodeViewRsdsSignature) {
      continue;
    }
    std::copy_n(header.begin() + 4, event.pdb_guid.size(), event.pdb_guid.begin());
    std::memcpy(&event.pdb_age, header.data() + 20, sizeof(event.pdb_age));
    set_flag(event, RawModuleEventFlag::kHasPdbIdentity);

    const std::size_t available = static_cast<std::size_t>(entry.SizeOfData) - header.size();
    const std::size_t to_read = (std::min)(available, event.pdb_path.size());
    if (to_read != 0U &&
        read_process_bytes(event.base_address,
                           static_cast<std::uint64_t>(entry.AddressOfRawData) + header.size(),
                           event.pdb_path.data(), to_read)) {
      const auto terminator =
          std::find(event.pdb_path.begin(), event.pdb_path.begin() + to_read, '\0');
      event.pdb_path_length =
          static_cast<std::uint16_t>(std::distance(event.pdb_path.begin(), terminator));
      if (terminator == event.pdb_path.begin() + to_read && available > to_read) {
        set_flag(event, RawModuleEventFlag::kPdbPathTruncated);
      }
    }
    return;
  }
}

void capture_image_identity(RawModuleEvent& event) noexcept {
  IMAGE_DOS_HEADER dos{};
  if (!read_process_value(event.base_address, 0U, dos) || dos.e_magic != IMAGE_DOS_SIGNATURE ||
      dos.e_lfanew <= 0) {
    return;
  }
  const std::uint64_t nt_offset = static_cast<std::uint32_t>(dos.e_lfanew);
  DWORD signature = 0U;
  IMAGE_FILE_HEADER file_header{};
  if (!read_process_value(event.base_address, nt_offset, signature) ||
      signature != IMAGE_NT_SIGNATURE ||
      !read_process_value(event.base_address, nt_offset + sizeof(signature), file_header)) {
    return;
  }
  WORD magic = 0U;
  const std::uint64_t optional_offset = nt_offset + sizeof(signature) + sizeof(IMAGE_FILE_HEADER);
  if (!read_process_value(event.base_address, optional_offset, magic)) {
    return;
  }

  std::uint32_t image_size = 0U;
  std::uint32_t checksum = 0U;
  IMAGE_DATA_DIRECTORY debug_directory{};
  if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC &&
      file_header.SizeOfOptionalHeader >= sizeof(IMAGE_OPTIONAL_HEADER64)) {
    IMAGE_OPTIONAL_HEADER64 optional{};
    if (!read_process_value(event.base_address, optional_offset, optional)) {
      return;
    }
    image_size = optional.SizeOfImage;
    checksum = optional.CheckSum;
    if (optional.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_DEBUG) {
      debug_directory = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
    }
  } else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC &&
             file_header.SizeOfOptionalHeader >= sizeof(IMAGE_OPTIONAL_HEADER32)) {
    IMAGE_OPTIONAL_HEADER32 optional{};
    if (!read_process_value(event.base_address, optional_offset, optional)) {
      return;
    }
    image_size = optional.SizeOfImage;
    checksum = optional.CheckSum;
    if (optional.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_DEBUG) {
      debug_directory = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
    }
  } else {
    return;
  }
  if (image_size == 0U) {
    return;
  }
  event.image_size = image_size;
  event.pe_timestamp = file_header.TimeDateStamp;
  event.pe_checksum = checksum;
  set_flag(event, RawModuleEventFlag::kHasImageIdentity);
  capture_code_view(event, debug_directory);
}

void copy_unicode_path(RawModuleEvent& event, const UNICODE_STRING* path) noexcept {
  if (path == nullptr || path->Buffer == nullptr || path->Length == 0U) {
    return;
  }
  const std::size_t available = path->Length / sizeof(wchar_t);
  const std::size_t count = (std::min)(available, event.path.size());
  std::copy_n(path->Buffer, count, event.path.begin());
  event.path_length = static_cast<std::uint16_t>(count);
  if (available > count) {
    set_flag(event, RawModuleEventFlag::kPathTruncated);
  }
}

}  // namespace

class WindowsModuleTracker::Implementation final {
 public:
  Implementation(std::uint64_t monotonic_origin, std::size_t queue_capacity)
      : queue_{queue_capacity}, monotonic_origin_{monotonic_origin} {
    if (!hook_guard_runtime_is_ready()) {
      throw std::invalid_argument{"module tracker requires an initialized hook guard runtime"};
    }
    const InternalThreadScope internal_thread;
    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == nullptr) {
      throw std::runtime_error{"cannot locate ntdll for module notifications"};
    }
    register_notification_ = reinterpret_cast<RegisterDllNotification>(
        GetProcAddress(ntdll, "LdrRegisterDllNotification"));
    unregister_notification_ = reinterpret_cast<UnregisterDllNotification>(
        GetProcAddress(ntdll, "LdrUnregisterDllNotification"));
    if (register_notification_ == nullptr || unregister_notification_ == nullptr) {
      throw std::runtime_error{"Windows loader notifications are unavailable"};
    }
    const NTSTATUS status = register_notification_(0U, &notification_callback, this, &cookie_);
    if (!nt_success(status) || cookie_ == nullptr) {
      throw std::runtime_error{"LdrRegisterDllNotification failed"};
    }
    try {
      enumerate_initial_modules();
    } catch (...) {
      static_cast<void>(unregister_notification_(cookie_));
      cookie_ = nullptr;
      throw;
    }
  }

  ~Implementation() {
    if (cookie_ != nullptr) {
      const InternalThreadScope internal_thread;
      static_cast<void>(unregister_notification_(cookie_));
      cookie_ = nullptr;
    }
  }

  [[nodiscard]] std::span<const RawModuleEvent> initial_modules() const noexcept {
    return initial_modules_;
  }

  [[nodiscard]] bool try_dequeue(RawModuleEvent& event) noexcept { return queue_.try_pop(event); }

  [[nodiscard]] std::uint64_t take_dropped_event_count() noexcept {
    return queue_.take_dropped_count();
  }

  [[nodiscard]] std::size_t queue_capacity() const noexcept { return queue_.capacity(); }

  [[nodiscard]] bool is_registered() const noexcept { return cookie_ != nullptr; }

 private:
  static void CALLBACK notification_callback(ULONG reason, const DllNotificationData* data,
                                             void* context) noexcept {
    if (context == nullptr || data == nullptr) {
      return;
    }
    static_cast<Implementation*>(context)->handle_notification(reason, *data);
  }

  void handle_notification(ULONG reason, const DllNotificationData& data) noexcept {
    const DWORD last_error = GetLastError();
    {
      const InternalThreadScope internal_thread;
      if (reason == kDllNotificationReasonLoaded) {
        const auto& loaded = data.loaded;
        static_cast<void>(
            queue_.try_emplace([this, &loaded](RawModuleEvent& event, std::uint64_t) noexcept {
              event = {};
              event.type = RawModuleEventType::kLoad;
              event.monotonic_ticks = query_ticks(monotonic_origin_);
              event.base_address =
                  static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(loaded.dll_base));
              event.image_size = loaded.size_of_image;
              copy_unicode_path(event, loaded.full_dll_name);
              capture_image_identity(event);
            }));
      } else if (reason == kDllNotificationReasonUnloaded) {
        const auto& unloaded = data.unloaded;
        static_cast<void>(
            queue_.try_emplace([this, &unloaded](RawModuleEvent& event, std::uint64_t) noexcept {
              event = {};
              event.type = RawModuleEventType::kUnload;
              event.monotonic_ticks = query_ticks(monotonic_origin_);
              event.base_address =
                  static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(unloaded.dll_base));
              event.image_size = unloaded.size_of_image;
            }));
      }
    }
    SetLastError(last_error);
  }

  void enumerate_initial_modules() {
    std::vector<HMODULE> modules(256U);
    DWORD bytes_needed = 0U;
    for (;;) {
      if (K32EnumProcessModules(GetCurrentProcess(), modules.data(),
                                static_cast<DWORD>(modules.size() * sizeof(HMODULE)),
                                &bytes_needed) == FALSE) {
        throw std::runtime_error{"cannot enumerate initial process modules"};
      }
      const std::size_t needed = bytes_needed / sizeof(HMODULE);
      if (needed <= modules.size()) {
        modules.resize(needed);
        break;
      }
      modules.resize(needed);
    }

    initial_modules_.reserve(modules.size());
    for (HMODULE module : modules) {
      MODULEINFO information{};
      if (K32GetModuleInformation(GetCurrentProcess(), module, &information, sizeof(information)) ==
              FALSE ||
          information.lpBaseOfDll == nullptr || information.SizeOfImage == 0U) {
        continue;
      }
      RawModuleEvent event;
      event.type = RawModuleEventType::kLoad;
      event.monotonic_ticks = monotonic_origin_;
      event.base_address =
          static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(information.lpBaseOfDll));
      event.image_size = information.SizeOfImage;
      set_flag(event, RawModuleEventFlag::kInitialSnapshot);
      const DWORD path_length = K32GetModuleFileNameExW(
          GetCurrentProcess(), module, event.path.data(), static_cast<DWORD>(event.path.size()));
      event.path_length = static_cast<std::uint16_t>(path_length);
      if (path_length == event.path.size()) {
        set_flag(event, RawModuleEventFlag::kPathTruncated);
      }
      capture_image_identity(event);
      initial_modules_.push_back(event);
    }
    std::sort(initial_modules_.begin(), initial_modules_.end(),
              [](const RawModuleEvent& left, const RawModuleEvent& right) {
                return left.base_address < right.base_address;
              });
  }

  BoundedMpscQueue<RawModuleEvent> queue_;
  const std::uint64_t monotonic_origin_;
  RegisterDllNotification register_notification_{nullptr};
  UnregisterDllNotification unregister_notification_{nullptr};
  void* cookie_{nullptr};
  std::vector<RawModuleEvent> initial_modules_;
};

WindowsModuleTracker::WindowsModuleTracker(std::uint64_t monotonic_origin,
                                           std::size_t queue_capacity)
    : implementation_{std::make_unique<Implementation>(monotonic_origin, queue_capacity)} {}

WindowsModuleTracker::~WindowsModuleTracker() = default;

std::span<const RawModuleEvent> WindowsModuleTracker::initial_modules() const noexcept {
  return implementation_->initial_modules();
}

bool WindowsModuleTracker::try_dequeue(RawModuleEvent& event) noexcept {
  return implementation_->try_dequeue(event);
}

std::uint64_t WindowsModuleTracker::take_dropped_event_count() noexcept {
  return implementation_->take_dropped_event_count();
}

std::size_t WindowsModuleTracker::queue_capacity() const noexcept {
  return implementation_->queue_capacity();
}

bool WindowsModuleTracker::is_registered() const noexcept {
  return implementation_->is_registered();
}

}  // namespace noleax::agent::windows
