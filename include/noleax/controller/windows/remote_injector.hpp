#pragma once

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <stdexcept>

#include "noleax/agent/windows/bootstrap.hpp"

namespace noleax::controller::windows {

struct InjectionResult {
  std::uintptr_t remote_module_base{0U};
  std::uint32_t load_thread_id{0U};
  std::uint32_t bootstrap_thread_id{0U};
};

class InjectionError final : public std::runtime_error {
 public:
  InjectionError(const std::string& message, std::uint32_t system_error);
  [[nodiscard]] std::uint32_t system_error() const noexcept;

 private:
  std::uint32_t system_error_{0U};
};

[[nodiscard]] InjectionResult inject_remote_thread(
    void* process_handle, std::uint32_t process_id, const std::filesystem::path& agent_path,
    const noleax::agent::windows::BootstrapParameters& bootstrap,
    std::chrono::milliseconds timeout);

}  // namespace noleax::controller::windows
