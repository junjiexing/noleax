#pragma once

// Internal helpers shared by the Windows injection strategies (remote thread,
// thread hijack and entrypoint code). This header is private to the
// noleax-controller implementation and must not be installed or included from
// public headers.

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
// clang-format off: tlhelp32.h and psapi.h require Windows base types.
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
// clang-format on

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include "noleax/controller/windows/remote_injector.hpp"

namespace noleax::controller::windows::injection {

class Handle final {
 public:
  explicit Handle(HANDLE value = nullptr) noexcept : value_{value} {}
  ~Handle() {
    if (value_ != nullptr && value_ != INVALID_HANDLE_VALUE) {
      static_cast<void>(CloseHandle(value_));
    }
  }

  Handle(const Handle&) = delete;
  Handle& operator=(const Handle&) = delete;

  Handle(Handle&& other) noexcept : value_{std::exchange(other.value_, nullptr)} {}
  Handle& operator=(Handle&& other) noexcept {
    if (this != &other) {
      if (value_ != nullptr && value_ != INVALID_HANDLE_VALUE) {
        static_cast<void>(CloseHandle(value_));
      }
      value_ = std::exchange(other.value_, nullptr);
    }
    return *this;
  }

  [[nodiscard]] HANDLE get() const noexcept { return value_; }
  [[nodiscard]] bool valid() const noexcept {
    return value_ != nullptr && value_ != INVALID_HANDLE_VALUE;
  }
  [[nodiscard]] HANDLE release() noexcept { return std::exchange(value_, nullptr); }

 private:
  HANDLE value_{nullptr};
};

class RemoteMemory final {
 public:
  RemoteMemory(HANDLE process, std::size_t size);
  ~RemoteMemory();

  RemoteMemory(const RemoteMemory&) = delete;
  RemoteMemory& operator=(const RemoteMemory&) = delete;

  [[nodiscard]] void* get() const noexcept { return address_; }
  [[nodiscard]] std::size_t size() const noexcept { return size_; }
  void preserve_for_timed_out_remote_thread() noexcept { owned_ = false; }

  void protect(DWORD protection);
  void write(const void* bytes, std::size_t size) { write_at(0U, bytes, size); }
  void write_at(std::size_t offset, const void* bytes, std::size_t size);
  void read(void* bytes, std::size_t size) const { read_at(0U, bytes, size); }
  void read_at(std::size_t offset, void* bytes, std::size_t size) const;

 private:
  HANDLE process_{nullptr};
  void* address_{nullptr};
  std::size_t size_{0U};
  bool owned_{true};
};

struct RemoteModule {
  std::uintptr_t base{0U};
  std::wstring path;
};

[[noreturn]] void fail(const char* operation, DWORD error);

[[nodiscard]] bool equal_case_insensitive(std::wstring_view left, std::wstring_view right) noexcept;

[[nodiscard]] std::optional<RemoteModule> find_remote_module(std::uint32_t process_id,
                                                             std::wstring_view module_name);
[[nodiscard]] std::optional<RemoteModule> find_remote_image_by_memory(
    HANDLE process, std::wstring_view module_name);
[[nodiscard]] std::optional<RemoteModule> find_remote_module_resilient(
    HANDLE process, std::uint32_t process_id, std::wstring_view module_name);

[[nodiscard]] std::uintptr_t checked_remote_address(std::uintptr_t base, std::uintptr_t offset);
[[nodiscard]] std::uintptr_t local_procedure_offset(HMODULE module, const char* name);

struct RemoteThreadResult {
  std::uint32_t thread_id{0U};
  std::uint32_t exit_code{0U};
};

[[nodiscard]] RemoteThreadResult run_remote_thread(HANDLE process, std::uintptr_t procedure,
                                                   void* parameter,
                                                   std::chrono::milliseconds timeout,
                                                   RemoteMemory* parameter_memory,
                                                   RemoteMemory* procedure_memory = nullptr);

[[nodiscard]] std::uintptr_t remote_ntdll_procedure(HANDLE process, std::uint32_t process_id,
                                                    const char* name);

// Reads SizeOfImage from the remote PE header of a mapped image.
[[nodiscard]] std::uint32_t remote_image_size(HANDLE process, std::uintptr_t image_base);

// Reads AddressOfEntryPoint from the remote PE header of a mapped image.
[[nodiscard]] std::uint32_t remote_entry_point_rva(HANDLE process, std::uintptr_t image_base);

void try_unload_remote_module(HANDLE process, std::uint32_t process_id,
                              std::uintptr_t remote_module,
                              std::chrono::milliseconds timeout) noexcept;

}  // namespace noleax::controller::windows::injection
