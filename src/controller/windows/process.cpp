#include "noleax/controller/windows/process.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace noleax::controller::windows {
namespace {

[[nodiscard]] HANDLE as_handle(void* value) noexcept { return static_cast<HANDLE>(value); }

[[nodiscard]] void* as_storage(HANDLE value) noexcept { return static_cast<void*>(value); }

void close_handle(void*& value) noexcept {
  if (value != nullptr && as_handle(value) != INVALID_HANDLE_VALUE) {
    static_cast<void>(CloseHandle(as_handle(value)));
  }
  value = nullptr;
}

[[nodiscard]] DWORD timeout_milliseconds(std::chrono::milliseconds timeout) {
  if (timeout < std::chrono::milliseconds::zero()) {
    throw ProcessError{"process wait timeout must not be negative", ERROR_INVALID_PARAMETER};
  }
  return timeout.count() >= static_cast<long long>(INFINITE - 1U)
             ? INFINITE - 1U
             : static_cast<DWORD>(timeout.count());
}

[[nodiscard]] std::wstring build_command_line(const std::filesystem::path& executable,
                                              const std::vector<std::string>& arguments) {
  std::wstring command_line = quote_windows_argument(executable.native());
  for (const std::string& argument : arguments) {
    command_line.push_back(L' ');
    command_line.append(quote_windows_argument(utf8_to_wide(argument)));
  }
  return command_line;
}

}  // namespace

ProcessError::ProcessError(const std::string& message, std::uint32_t system_error)
    : std::runtime_error{message}, system_error_{system_error} {}

std::uint32_t ProcessError::system_error() const noexcept { return system_error_; }

SuspendedProcess::~SuspendedProcess() {
  close_handle(main_thread_);
  close_handle(process_);
}

SuspendedProcess::SuspendedProcess(SuspendedProcess&& other) noexcept
    : process_{std::exchange(other.process_, nullptr)},
      main_thread_{std::exchange(other.main_thread_, nullptr)},
      process_id_{std::exchange(other.process_id_, 0U)},
      main_thread_suspended_{std::exchange(other.main_thread_suspended_, false)} {}

SuspendedProcess& SuspendedProcess::operator=(SuspendedProcess&& other) noexcept {
  if (this != &other) {
    close_handle(main_thread_);
    close_handle(process_);
    process_ = std::exchange(other.process_, nullptr);
    main_thread_ = std::exchange(other.main_thread_, nullptr);
    process_id_ = std::exchange(other.process_id_, 0U);
    main_thread_suspended_ = std::exchange(other.main_thread_suspended_, false);
  }
  return *this;
}

SuspendedProcess SuspendedProcess::create(const std::filesystem::path& executable,
                                          const std::vector<std::string>& arguments,
                                          const std::filesystem::path& working_directory) {
  if (executable.empty() || !executable.is_absolute()) {
    throw ProcessError{"target executable path must be absolute", ERROR_INVALID_PARAMETER};
  }
  std::error_code path_error;
  if (!std::filesystem::is_regular_file(executable, path_error) || path_error) {
    throw ProcessError{"target executable does not exist or is not a regular file",
                       ERROR_FILE_NOT_FOUND};
  }
  if (!working_directory.empty() &&
      (!std::filesystem::is_directory(working_directory, path_error) || path_error)) {
    throw ProcessError{"target working directory does not exist", ERROR_DIRECTORY};
  }

  std::wstring command_line = build_command_line(executable, arguments);
  std::vector<wchar_t> mutable_command_line(command_line.begin(), command_line.end());
  mutable_command_line.push_back(L'\0');
  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  PROCESS_INFORMATION information{};
  const wchar_t* current_directory =
      working_directory.empty() ? nullptr : working_directory.c_str();
  if (CreateProcessW(executable.c_str(), mutable_command_line.data(), nullptr, nullptr, FALSE,
                     CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT, nullptr, current_directory,
                     &startup, &information) == FALSE) {
    const DWORD error = GetLastError();
    throw ProcessError{"CreateProcessW failed with Windows error " + std::to_string(error), error};
  }

  SuspendedProcess process;
  process.process_ = as_storage(information.hProcess);
  process.main_thread_ = as_storage(information.hThread);
  process.process_id_ = information.dwProcessId;
  process.main_thread_suspended_ = true;
  return process;
}

void SuspendedProcess::resume_main_thread() {
  if (!valid() || !main_thread_suspended_) {
    throw ProcessError{"target main thread is not suspended", ERROR_INVALID_PARAMETER};
  }
  if (ResumeThread(as_handle(main_thread_)) == std::numeric_limits<DWORD>::max()) {
    const DWORD error = GetLastError();
    throw ProcessError{"ResumeThread failed with Windows error " + std::to_string(error), error};
  }
  main_thread_suspended_ = false;
}

void SuspendedProcess::note_main_thread_resumed() noexcept { main_thread_suspended_ = false; }

void SuspendedProcess::terminate(std::uint32_t exit_code_value) noexcept {
  if (valid()) {
    static_cast<void>(TerminateProcess(as_handle(process_), exit_code_value));
    static_cast<void>(WaitForSingleObject(as_handle(process_), 30'000U));
  }
}

bool SuspendedProcess::wait(std::chrono::milliseconds timeout) const {
  if (!valid()) {
    throw ProcessError{"cannot wait for an invalid process", ERROR_INVALID_HANDLE};
  }
  const DWORD result = WaitForSingleObject(as_handle(process_), timeout_milliseconds(timeout));
  if (result == WAIT_OBJECT_0) {
    return true;
  }
  if (result == WAIT_TIMEOUT) {
    return false;
  }
  const DWORD error = GetLastError();
  throw ProcessError{"WaitForSingleObject failed with Windows error " + std::to_string(error),
                     error};
}

std::uint32_t SuspendedProcess::exit_code() const {
  if (!valid()) {
    throw ProcessError{"cannot query an invalid process", ERROR_INVALID_HANDLE};
  }
  DWORD code = 0U;
  if (GetExitCodeProcess(as_handle(process_), &code) == FALSE) {
    const DWORD error = GetLastError();
    throw ProcessError{"GetExitCodeProcess failed with Windows error " + std::to_string(error),
                       error};
  }
  return code;
}

std::uint32_t SuspendedProcess::process_id() const noexcept { return process_id_; }

void* SuspendedProcess::process_handle() const noexcept { return process_; }

void* SuspendedProcess::main_thread_handle() const noexcept { return main_thread_; }

bool SuspendedProcess::main_thread_is_suspended() const noexcept { return main_thread_suspended_; }

bool SuspendedProcess::valid() const noexcept {
  return process_ != nullptr && main_thread_ != nullptr && process_id_ != 0U;
}

std::wstring utf8_to_wide(std::string_view value) {
  if (value.empty()) {
    return {};
  }
  if (value.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
    throw ProcessError{"UTF-8 input is too long", ERROR_BUFFER_OVERFLOW};
  }
  const int input_size = static_cast<int>(value.size());
  const int size =
      MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), input_size, nullptr, 0);
  if (size <= 0) {
    const DWORD error = GetLastError();
    throw ProcessError{"invalid UTF-8 input", error};
  }
  std::wstring result(static_cast<std::size_t>(size), L'\0');
  if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), input_size, result.data(),
                          size) != size) {
    const DWORD error = GetLastError();
    throw ProcessError{"UTF-8 conversion failed", error};
  }
  return result;
}

std::string wide_to_utf8(std::wstring_view value) {
  if (value.empty()) {
    return {};
  }
  if (value.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
    throw ProcessError{"UTF-16 input is too long", ERROR_BUFFER_OVERFLOW};
  }
  const int input_size = static_cast<int>(value.size());
  const int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), input_size,
                                       nullptr, 0, nullptr, nullptr);
  if (size <= 0) {
    const DWORD error = GetLastError();
    throw ProcessError{"invalid UTF-16 input", error};
  }
  std::string result(static_cast<std::size_t>(size), '\0');
  if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), input_size, result.data(),
                          size, nullptr, nullptr) != size) {
    const DWORD error = GetLastError();
    throw ProcessError{"UTF-16 conversion failed", error};
  }
  return result;
}

std::wstring quote_windows_argument(std::wstring_view argument) {
  if (argument.empty()) {
    return L"\"\"";
  }
  const bool requires_quotes = argument.find_first_of(L" \t\n\v\"") != std::wstring_view::npos;
  if (!requires_quotes) {
    return std::wstring{argument};
  }
  std::wstring result;
  result.push_back(L'\"');
  std::size_t backslashes = 0U;
  for (const wchar_t character : argument) {
    if (character == L'\\') {
      ++backslashes;
      continue;
    }
    if (character == L'\"') {
      result.append(backslashes * 2U + 1U, L'\\');
      result.push_back(L'\"');
      backslashes = 0U;
      continue;
    }
    result.append(backslashes, L'\\');
    backslashes = 0U;
    result.push_back(character);
  }
  result.append(backslashes * 2U, L'\\');
  result.push_back(L'\"');
  return result;
}

}  // namespace noleax::controller::windows
