#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <stdexcept>

#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#endif

namespace noleax::testing {

#ifdef _WIN32

class LoadedImage {
 public:
  explicit LoadedImage(const std::filesystem::path& path) : module_{LoadLibraryW(path.c_str())} {
    if (module_ == nullptr) {
      throw std::runtime_error{"cannot load symbolizer test image"};
    }
    const auto* base = reinterpret_cast<const std::byte*>(module_);
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0) {
      throw std::runtime_error{"symbolizer test image has an invalid DOS header"};
    }
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.SizeOfImage == 0U) {
      throw std::runtime_error{"symbolizer test image has an invalid NT header"};
    }
    base_ = reinterpret_cast<std::uintptr_t>(module_);
    size_ = nt->OptionalHeader.SizeOfImage;
  }

  ~LoadedImage() {
    if (module_ != nullptr) {
      FreeLibrary(module_);
    }
  }

  LoadedImage(const LoadedImage&) = delete;
  LoadedImage& operator=(const LoadedImage&) = delete;

  [[nodiscard]] std::uint32_t size() const noexcept { return size_; }

  [[nodiscard]] std::uint64_t exported_offset(const char* name) const {
    const FARPROC address = GetProcAddress(module_, name);
    if (address == nullptr) {
      throw std::runtime_error{"symbolizer test export is unavailable"};
    }
    return reinterpret_cast<std::uintptr_t>(address) - base_;
  }

 private:
  HMODULE module_{nullptr};
  std::uintptr_t base_{0U};
  std::uint32_t size_{0U};
};

[[nodiscard]] inline std::filesystem::path symbol_fixture_path() {
  return std::filesystem::path{NOLEAX_SYMBOL_FIXTURE_PATH};
}

#endif

}  // namespace noleax::testing
