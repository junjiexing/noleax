#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>

namespace noleax::controller::windows {

class ThreadSuspensionError final : public std::runtime_error {
 public:
  ThreadSuspensionError(const std::string& message, std::uint32_t system_error);
  [[nodiscard]] std::uint32_t system_error() const noexcept;

 private:
  std::uint32_t system_error_{0U};
};

class ThreadSuspension final {
 public:
  ThreadSuspension(std::uint32_t process_id, std::uint32_t excluded_thread_id);
  ~ThreadSuspension();

  ThreadSuspension(const ThreadSuspension&) = delete;
  ThreadSuspension& operator=(const ThreadSuspension&) = delete;
  ThreadSuspension(ThreadSuspension&&) = delete;
  ThreadSuspension& operator=(ThreadSuspension&&) = delete;

  [[nodiscard]] std::size_t suspended_count() const noexcept;

 private:
  class Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace noleax::controller::windows
