#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include "noleax/agent/hook_backend.hpp"
#include "noleax/agent/windows/rtl_allocate_heap_trace_writer.hpp"
#include "noleax/agent/windows/rtl_heap_hooks.hpp"
#include "noleax/analyzer/event_stream.hpp"
#include "noleax/analyzer/symbolizer.hpp"
#include "noleax/trace/event.hpp"
#include "noleax/trace/module.hpp"
#include "noleax/trace/stack.hpp"
#include "noleax/trace/wire_format.hpp"

namespace {

using AllocateFunction = void*(NTAPI*)(void* heap, unsigned long flags, std::size_t size);
using FixtureAllocate = void* (*)(AllocateFunction allocate, void* heap, std::size_t size);

[[nodiscard]] noleax::trace::FileHeader file_header() {
  LARGE_INTEGER frequency{};
  LARGE_INTEGER origin{};
  if (QueryPerformanceFrequency(&frequency) == FALSE || QueryPerformanceCounter(&origin) == FALSE) {
    throw std::runtime_error{"QueryPerformanceCounter is unavailable"};
  }
  noleax::trace::FileHeader header;
  header.pointer_width = 8U;
  header.platform = noleax::trace::Platform::kWindows;
  header.architecture = noleax::trace::Architecture::kX64;
  header.monotonic_frequency = static_cast<std::uint64_t>(frequency.QuadPart);
  header.monotonic_origin = static_cast<std::uint64_t>(origin.QuadPart);
  header.session_id[0] = std::byte{0x56};
  return header;
}

[[nodiscard]] std::wstring absolute_wide_path(const char* value) {
  return std::filesystem::absolute(std::filesystem::path{value}).wstring();
}

[[nodiscard]] HMODULE load_fixture(const std::wstring& path) {
  HMODULE module = LoadLibraryW(path.c_str());
  if (module == nullptr) {
    throw std::runtime_error{"cannot load module-generation fixture"};
  }
  return module;
}

[[nodiscard]] FixtureAllocate fixture_function(HMODULE module) {
  const auto function = reinterpret_cast<FixtureAllocate>(
      GetProcAddress(module, "noleax_module_generation_allocate"));
  if (function == nullptr) {
    throw std::runtime_error{"cannot resolve module-generation fixture export"};
  }
  return function;
}

struct DecodedTrace {
  std::vector<noleax::trace::ModuleLoad> loads;
  std::vector<noleax::trace::ModuleUnload> unloads;
  std::unordered_map<std::uint64_t, noleax::trace::StackDefinition> stacks;
  std::unordered_map<std::uint64_t, noleax::trace::StackId> allocation_stacks;
  noleax::analyzer::EventStreamResult result;
};

[[nodiscard]] DecodedTrace decode_trace(const std::filesystem::path& path) {
  std::ifstream input{path, std::ios::binary};
  if (!input) {
    throw std::runtime_error{"cannot open module-generation trace"};
  }
  DecodedTrace decoded;
  noleax::analyzer::EventStreamCallbacks callbacks;
  callbacks.on_module_load = [&decoded](const noleax::trace::ModuleLoad& load) {
    decoded.loads.push_back(load);
  };
  callbacks.on_module_unload = [&decoded](const noleax::trace::ModuleUnload& unload) {
    decoded.unloads.push_back(unload);
  };
  callbacks.on_stack_definition = [&decoded](const noleax::trace::StackDefinition& stack) {
    decoded.stacks.emplace(stack.stack_id.value(), stack);
  };
  callbacks.on_event = [&decoded](const noleax::trace::Event& event) {
    const auto* allocation = std::get_if<noleax::trace::AllocationEvent>(&event.payload);
    if (allocation != nullptr &&
        (allocation->requested_size == 12345U || allocation->requested_size == 12346U)) {
      decoded.allocation_stacks.emplace(allocation->requested_size, event.header.stack_id);
    }
  };
  decoded.result = noleax::analyzer::analyze_event_stream(input, callbacks);
  return decoded;
}

[[nodiscard]] std::optional<noleax::trace::StackFrame> fixture_frame(
    const DecodedTrace& trace, std::uint64_t requested_size, noleax::trace::ModuleId module_id) {
  const auto stack_id = trace.allocation_stacks.find(requested_size);
  if (stack_id == trace.allocation_stacks.end()) {
    return std::nullopt;
  }
  const auto stack = trace.stacks.find(stack_id->second.value());
  if (stack == trace.stacks.end()) {
    return std::nullopt;
  }
  const auto frame = std::find_if(stack->second.frames.begin(), stack->second.frames.end(),
                                  [module_id](const noleax::trace::StackFrame& candidate) {
                                    return candidate.module_id == module_id;
                                  });
  if (frame == stack->second.frames.end()) {
    return std::nullopt;
  }
  return *frame;
}

[[nodiscard]] noleax::analyzer::SymbolModule symbol_module(const noleax::trace::ModuleLoad& load) {
  noleax::analyzer::SymbolModule module;
  module.module_id = load.module_id;
  module.base_address = load.base_address;
  module.image_size = load.image_size;
  module.image_path = std::filesystem::path{load.image_path};
  module.expected_image_identity = load.image_identity;
  module.expected_pdb_identity = load.pdb_identity;
  return module;
}

}  // namespace

int main(int argc, char** argv) {
  try {
    if (argc != 3) {
      std::cerr << "usage: module_generation_trace_test FIXTURE TRACE\n";
      return 2;
    }
    const std::wstring fixture_path = absolute_wide_path(argv[1]);
    const std::filesystem::path trace_path = std::filesystem::absolute(argv[2]);
    std::ofstream output{trace_path, std::ios::binary | std::ios::trunc};
    if (!output) {
      throw std::runtime_error{"cannot create module-generation trace"};
    }

    noleax::agent::HookBackend backend;
    noleax::agent::windows::RtlHeapHooks hooks{backend};
    noleax::agent::windows::RtlAllocateHeapTraceWriter writer{
        hooks.create_hook(), hooks.allocate_hook(), hooks.reallocate_hook(),
        hooks.free_hook(),   hooks.destroy_hook(),  output,
        file_header()};
    const auto install = hooks.install();
    if (!install.installed()) {
      throw std::runtime_error{"cannot install NT Heap profile for module-generation test"};
    }
    writer.begin_capture();

    HMODULE first_module = load_fixture(fixture_path);
    const std::uint64_t first_base =
        static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(first_module));
    void* first_allocation = fixture_function(first_module)(
        reinterpret_cast<AllocateFunction>(hooks.allocate_hook().target_address()),
        GetProcessHeap(), 12345U);
    if (first_allocation == nullptr || HeapFree(GetProcessHeap(), 0U, first_allocation) == FALSE) {
      throw std::runtime_error{"first fixture allocation failed"};
    }
    if (FreeLibrary(first_module) == FALSE) {
      throw std::runtime_error{"cannot unload first module generation"};
    }

    HMODULE second_module = load_fixture(fixture_path);
    const std::uint64_t second_base =
        static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(second_module));
    void* second_allocation = fixture_function(second_module)(
        reinterpret_cast<AllocateFunction>(hooks.allocate_hook().target_address()),
        GetProcessHeap(), 12346U);
    if (second_allocation == nullptr ||
        HeapFree(GetProcessHeap(), 0U, second_allocation) == FALSE) {
      throw std::runtime_error{"second fixture allocation failed"};
    }
    if (FreeLibrary(second_module) == FALSE) {
      throw std::runtime_error{"cannot unload second module generation"};
    }

    if (!hooks.uninstall()) {
      throw std::runtime_error{"cannot uninstall NT Heap profile"};
    }
    const auto writer_result = writer.finish();
    output.close();
    if (writer_result.status !=
            noleax::agent::windows::RtlAllocateHeapTraceWriterStatus::kComplete ||
        writer_result.module_notification_drops != 0U) {
      throw std::runtime_error{"module-generation writer did not complete losslessly"};
    }

    const DecodedTrace decoded = decode_trace(trace_path);
    std::vector<noleax::trace::ModuleLoad> fixture_loads;
    std::copy_if(decoded.loads.begin(), decoded.loads.end(), std::back_inserter(fixture_loads),
                 [&fixture_path](const noleax::trace::ModuleLoad& load) {
                   return std::filesystem::path{load.image_path}.filename() ==
                          std::filesystem::path{fixture_path}.filename();
                 });
    if (fixture_loads.size() != 2U || first_base != second_base ||
        fixture_loads[0].base_address != fixture_loads[1].base_address ||
        fixture_loads[0].module_id == fixture_loads[1].module_id) {
      throw std::runtime_error{"fixture module generations were not distinguished at reused base"};
    }
    const auto first_frame = fixture_frame(decoded, 12345U, fixture_loads[0].module_id);
    const auto second_frame = fixture_frame(decoded, 12346U, fixture_loads[1].module_id);
    if (!first_frame.has_value() || !second_frame.has_value() ||
        first_frame->module_offset != second_frame->module_offset ||
        first_frame->absolute_address != second_frame->absolute_address ||
        decoded.allocation_stacks.at(12345U) == decoded.allocation_stacks.at(12346U)) {
      throw std::runtime_error{"normalized fixture stacks do not preserve module generations"};
    }
    const bool first_unloaded =
        std::any_of(decoded.unloads.begin(), decoded.unloads.end(),
                    [&fixture_loads](const noleax::trace::ModuleUnload& unload) {
                      return unload.module_id == fixture_loads[0].module_id;
                    });
    if (!first_unloaded) {
      throw std::runtime_error{"first fixture module generation was not unloaded"};
    }

    noleax::analyzer::OfflineSymbolizer symbolizer;
    const auto symbol_status = symbolizer.register_module(symbol_module(fixture_loads[0]));
    const auto resolved =
        symbolizer.resolve_frame(fixture_loads[0].module_id, first_frame->absolute_address);
    if ((symbol_status.status != noleax::analyzer::SymbolModuleStatus::kSymbolsLoaded &&
         symbol_status.status != noleax::analyzer::SymbolModuleStatus::kExportsOnly) ||
        !resolved.module_offset.has_value() || *resolved.module_offset == 0U) {
      throw std::runtime_error{"offline symbolization did not resolve the unloaded generation"};
    }

    std::cout << "status=ok loads=" << fixture_loads.size() << " unload=1 base-reuse=1 "
              << "relative-stack=1 symbolized=1 events=" << decoded.result.event_count << '\n';
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "status=error message=" << error.what() << '\n';
    return 1;
  }
}
