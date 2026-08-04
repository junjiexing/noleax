// Target for the custom symbol hook e2e test. Loads the fixture allocator DLLs, signals
// readiness through marker files, and runs a deterministic allocation sequence with
// distinctive sizes once the test says the hooks are recording.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <cstddef>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>

namespace {

using AllocFunction = void*(NTAPI*)(void*, std::size_t);
using InternalAllocFunction = void*(NTAPI*)(std::size_t);
using FreeFunction = void(NTAPI*)(void*);
using ReallocFunction = void*(NTAPI*)(void*, std::size_t);
using CallocFunction = void*(NTAPI*)(std::size_t, std::size_t);
using XallocFunction = int(NTAPI*)(void**, std::size_t);
using FreeSizeFunction = void(NTAPI*)(void*, std::size_t);

AllocFunction g_malloc = nullptr;
FreeFunction g_free_a = nullptr;
FreeFunction g_free_b = nullptr;
ReallocFunction g_realloc = nullptr;
CallocFunction g_calloc = nullptr;
XallocFunction g_xalloc = nullptr;
FreeSizeFunction g_free_size = nullptr;
InternalAllocFunction g_malloc_internal = nullptr;
FreeFunction g_free_internal = nullptr;

[[nodiscard]] std::wstring widen(const char* value) {
  const int length = static_cast<int>(std::strlen(value));
  const int size = MultiByteToWideChar(CP_UTF8, 0, value, length, nullptr, 0);
  std::wstring result(static_cast<std::size_t>(size), L'\0');
  static_cast<void>(MultiByteToWideChar(CP_UTF8, 0, value, length, result.data(), size));
  return result;
}

void write_marker(const std::filesystem::path& path, const std::string& content) {
  std::ofstream output{path, std::ios::binary | std::ios::trunc};
  output << content;
}

[[nodiscard]] bool marker_exists(const std::filesystem::path& path) {
  std::error_code error;
  return std::filesystem::exists(path, error) && !error;
}

void wait_for_marker(const std::filesystem::path& path, std::uint32_t timeout_ms) {
  const ULONGLONG deadline = GetTickCount64() + timeout_ms;
  while (!marker_exists(path) && GetTickCount64() < deadline) {
    Sleep(10U);
  }
}

[[nodiscard]] HMODULE load_fixture(const std::filesystem::path& directory, const wchar_t* name) {
  const auto path = directory / name;
  return LoadLibraryW(path.c_str());
}

template <typename Function>
[[nodiscard]] bool resolve(HMODULE module, const char* name, Function& target) {
  target = reinterpret_cast<Function>(GetProcAddress(module, name));
  return target != nullptr;
}

[[nodiscard]] int load_and_resolve(const std::filesystem::path& directory) {
  const HMODULE module_a = load_fixture(directory, L"noleax-custom-alloc-a.dll");
  const HMODULE module_b = load_fixture(directory, L"noleax-custom-alloc-b.dll");
  const HMODULE module_c = load_fixture(directory, L"noleax-custom-alloc-c.dll");
  if (module_a == nullptr || module_b == nullptr || module_c == nullptr) {
    return 2;
  }
  if (!resolve(module_a, "my_malloc", g_malloc) || !resolve(module_a, "my_free", g_free_a) ||
      !resolve(module_a, "my_realloc", g_realloc) ||
      !resolve(module_a, "my_malloc_internal", g_malloc_internal) ||
      !resolve(module_a, "my_free_internal", g_free_internal) ||
      !resolve(module_b, "my_calloc", g_calloc) || !resolve(module_b, "my_free", g_free_b) ||
      !resolve(module_c, "my_xalloc", g_xalloc) ||
      !resolve(module_c, "my_free_size", g_free_size)) {
    return 3;
  }
  return 0;
}

[[nodiscard]] int run_sequence() {
  void* first = g_malloc(nullptr, 0x1111U);
  void* second = g_malloc(nullptr, 0x2222U);
  void* calloc_block = g_calloc(4U, 0x100U);
  void* xalloc_block = nullptr;
  const int xalloc_status = g_xalloc(&xalloc_block, 0x3333U);
  void* internal_block = g_malloc_internal(0x6666U);
  if (first == nullptr || second == nullptr || calloc_block == nullptr || xalloc_status != 0 ||
      xalloc_block == nullptr || internal_block == nullptr) {
    return 4;
  }
  second = g_realloc(second, 0x4444U);
  if (second == nullptr) {
    return 5;
  }
  g_free_a(first);
  g_free_b(calloc_block);
  g_free_size(xalloc_block, 0x3333U);
  g_free_internal(internal_block);
  // Deliberately leaked: the 0x5555-byte block and the reallocated 0x4444-byte block.
  static void* leaked = nullptr;
  leaked = g_malloc(nullptr, 0x5555U);
  return leaked == nullptr ? 6 : 0;
}

}  // namespace

int main(int argc, char* argv[]) {
  if (argc != 4) {
    return 10;
  }
  const std::filesystem::path directory = widen(argv[1]);
  const std::filesystem::path prefix = widen(argv[2]);
  const std::string mode = argv[3];
  const auto ready = prefix.parent_path() / (prefix.filename().wstring() + L".ready");
  const auto go = prefix.parent_path() / (prefix.filename().wstring() + L".go");
  const auto go2 = prefix.parent_path() / (prefix.filename().wstring() + L".go2");
  const auto loaded = prefix.parent_path() / (prefix.filename().wstring() + L".loaded");
  const auto done = prefix.parent_path() / (prefix.filename().wstring() + L".done");
  const auto exit_marker = prefix.parent_path() / (prefix.filename().wstring() + L".exit");

  if (mode == "basic") {
    const int status = load_and_resolve(directory);
    if (status != 0) {
      return status;
    }
    write_marker(ready, "ready=0\n");
    wait_for_marker(go, 60'000U);
    const int sequence = run_sequence();
    write_marker(done, "done=" + std::to_string(sequence) + "\n");
    wait_for_marker(exit_marker, 60'000U);
    return sequence;
  }
  if (mode == "late") {
    write_marker(ready, "ready=0\n");
    wait_for_marker(go, 60'000U);
    const int status = load_and_resolve(directory);
    if (status != 0) {
      return status;
    }
    write_marker(loaded, "loaded=0\n");
    wait_for_marker(go2, 60'000U);
    const int sequence = run_sequence();
    write_marker(done, "done=" + std::to_string(sequence) + "\n");
    wait_for_marker(exit_marker, 60'000U);
    return sequence;
  }
  return 11;
}
