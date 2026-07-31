#pragma once

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace noleax::controller::windows {

class ProcessError final : public std::runtime_error {
 public:
  ProcessError(const std::string& message, std::uint32_t system_error);
  [[nodiscard]] std::uint32_t system_error() const noexcept;

 private:
  std::uint32_t system_error_{0U};
};

class SuspendedProcess final {
 public:
  SuspendedProcess() noexcept = default;
  ~SuspendedProcess();

  SuspendedProcess(const SuspendedProcess&) = delete;
  SuspendedProcess& operator=(const SuspendedProcess&) = delete;
  SuspendedProcess(SuspendedProcess&& other) noexcept;
  SuspendedProcess& operator=(SuspendedProcess&& other) noexcept;

  [[nodiscard]] static SuspendedProcess create(const std::filesystem::path& executable,
                                               const std::vector<std::string>& arguments,
                                               const std::filesystem::path& working_directory = {});

  void resume_main_thread();
  void note_main_thread_resumed() noexcept;
  void terminate(std::uint32_t exit_code) noexcept;
  [[nodiscard]] bool wait(std::chrono::milliseconds timeout) const;
  [[nodiscard]] std::uint32_t exit_code() const;
  [[nodiscard]] std::uint32_t process_id() const noexcept;
  [[nodiscard]] void* process_handle() const noexcept;
  [[nodiscard]] void* main_thread_handle() const noexcept;
  [[nodiscard]] bool main_thread_is_suspended() const noexcept;
  [[nodiscard]] bool valid() const noexcept;

 private:
  void* process_{nullptr};
  void* main_thread_{nullptr};
  std::uint32_t process_id_{0U};
  bool main_thread_suspended_{false};
};

[[nodiscard]] std::wstring utf8_to_wide(std::string_view value);
[[nodiscard]] std::string wide_to_utf8(std::wstring_view value);
[[nodiscard]] std::wstring quote_windows_argument(std::wstring_view argument);

}  // namespace noleax::controller::windows
