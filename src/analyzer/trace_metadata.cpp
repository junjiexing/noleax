#include "noleax/analyzer/trace_metadata.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <istream>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>

#include "noleax/agent/windows/hook_registry.hpp"
#include "noleax/analyzer/event_stream.hpp"
#include "noleax/analyzer/filter.hpp"
#include "noleax/analyzer/presentation.hpp"
#include "noleax/analyzer/symbolizer.hpp"
#include "noleax/trace/event.hpp"
#include "noleax/trace/module.hpp"
#include "noleax/trace/stack.hpp"
#include "noleax/trace/wire_format.hpp"

namespace noleax::analyzer {
namespace {

[[nodiscard]] StackCaptureStatus presentation_status(
    noleax::trace::StackCaptureStatus status) noexcept {
  switch (status) {
    case noleax::trace::StackCaptureStatus::kComplete:
      return StackCaptureStatus::kComplete;
    case noleax::trace::StackCaptureStatus::kTruncatedByDepth:
      return StackCaptureStatus::kTruncatedByDepth;
    case noleax::trace::StackCaptureStatus::kUnwindFailed:
      return StackCaptureStatus::kUnwindFailed;
    case noleax::trace::StackCaptureStatus::kUnavailable:
      return StackCaptureStatus::kUnavailable;
  }
  return StackCaptureStatus::kUnavailable;
}

[[nodiscard]] std::string module_basename(std::string_view path) {
  const std::size_t separator = path.find_last_of("/\\");
  return std::string{separator == std::string_view::npos ? path : path.substr(separator + 1U)};
}

[[nodiscard]] bool is_agent_module_name(std::string_view module_name) {
  constexpr std::string_view kAgentName{"noleax-agent.dll"};
  const std::size_t separator = module_name.find_last_of("/\\");
  const std::string_view basename =
      separator == std::string_view::npos ? module_name : module_name.substr(separator + 1U);
  return basename.size() == kAgentName.size() &&
         std::equal(
             basename.begin(), basename.end(), kAgentName.begin(), [](char left, char right) {
               return (left >= 'A' && left <= 'Z' ? static_cast<char>(left - 'A' + 'a') : left) ==
                      right;
             });
}

[[nodiscard]] std::filesystem::path utf8_path(std::string_view value) {
  const auto* begin = reinterpret_cast<const char8_t*>(value.data());
  return std::filesystem::path{std::u8string{begin, begin + value.size()}};
}

}  // namespace

class TraceMetadata::Impl final {
 public:
  explicit Impl(const SymbolizerOptions& symbolizer_options) : symbolizer_{symbolizer_options} {}

  [[nodiscard]] EventStreamResult scan(std::istream& input, EventStreamOptions options) {
    if (scanned_) {
      throw TraceAnalysisError{"trace metadata has already been scanned"};
    }
    // A failed scan leaves the instance reusable but must not keep partial state from the
    // previous trace (module/stack id spaces overlap heavily across traces).
    modules_.clear();
    stacks_.clear();
    file_header_ = noleax::trace::FileHeader{};
    EventStreamCallbacks callbacks;
    callbacks.on_file_header = [this](const noleax::trace::FileHeader& header) {
      file_header_ = header;
    };
    callbacks.on_module_load = [this](const noleax::trace::ModuleLoad& load) {
      ModuleEntry entry;
      entry.load = load;
      try {
        SymbolModule module;
        module.module_id = load.module_id;
        module.base_address = load.base_address;
        module.image_size = load.image_size;
        module.image_path = utf8_path(load.image_path);
        module.expected_image_identity = load.image_identity;
        module.expected_pdb_identity = load.pdb_identity;
        static_cast<void>(symbolizer_.register_module(module));
        entry.registered = true;
      } catch (const SymbolizerError&) {
        entry.registered = false;
      }
      modules_.emplace(load.module_id.value(), std::move(entry));
    };
    callbacks.on_stack_definition = [this](const noleax::trace::StackDefinition& definition) {
      stacks_.emplace(definition.stack_id.value(), definition);
    };
    EventStreamResult result = analyze_event_stream(input, callbacks, options);
    scanned_ = true;
    return result;
  }

  void set_trim_agent_frames(bool enabled) noexcept { trim_agent_frames_ = enabled; }

  [[nodiscard]] EventMetadata metadata(const noleax::trace::Event& event) const {
    require_scanned();
    EventMetadata result;
    if (file_header_.platform == noleax::trace::Platform::kWindows) {
      if (const auto* api = noleax::agent::windows::find_windows_hook(event.header.api_id);
          api != nullptr) {
        result.api_name = std::string{api->canonical_name};
        result.api_module = std::string{api->module_name};
      }
    }
    const auto* stack = find_stack(event.header.stack_id);
    if (stack == nullptr) {
      return result;
    }
    result.stack_modules.reserve(stack->frames.size());
    for (const auto& frame : stack->frames) {
      const auto module = modules_.find(frame.module_id.value());
      if (frame.module_id.is_valid() && module != modules_.end()) {
        result.stack_modules.push_back(module->second.load.image_path);
      }
    }
    return result;
  }

  [[nodiscard]] EventPresentation presentation(const noleax::trace::Event& event) const {
    require_scanned();
    EventPresentation result;
    const EventMetadata event_metadata = metadata(event);
    result.api_name = event_metadata.api_name;
    result.api_module = event_metadata.api_module;
    const auto* stack = find_stack(event.header.stack_id);
    if (stack == nullptr) {
      return result;
    }
    result.stack_status = presentation_status(stack->status);
    result.stack_frames.reserve(stack->frames.size());
    for (const auto& frame : stack->frames) {
      ResolvedStackFrame resolved;
      resolved.absolute_address = frame.absolute_address;
      const auto module = modules_.find(frame.module_id.value());
      if (frame.module_id.is_valid() && module != modules_.end()) {
        if (module->second.registered) {
          try {
            resolved = symbolizer_.resolve_frame(frame.module_id, frame.absolute_address);
          } catch (const SymbolizerError&) {
          }
        }
        if (!resolved.module_name.has_value()) {
          resolved.module_name = module_basename(module->second.load.image_path);
          resolved.module_offset = frame.module_offset;
        }
      }
      result.stack_frames.push_back(std::move(resolved));
    }
    if (trim_agent_frames_) {
      result.stack_frames.erase(
          std::remove_if(result.stack_frames.begin(), result.stack_frames.end(),
                         [](const ResolvedStackFrame& frame) {
                           return frame.module_name.has_value() &&
                                  is_agent_module_name(*frame.module_name);
                         }),
          result.stack_frames.end());
    }
    return result;
  }

 private:
  struct ModuleEntry {
    noleax::trace::ModuleLoad load;
    bool registered{false};
  };

  void require_scanned() const {
    if (!scanned_) {
      throw TraceAnalysisError{"trace metadata has not been scanned"};
    }
  }

  [[nodiscard]] const noleax::trace::StackDefinition* find_stack(
      noleax::trace::StackId stack_id) const {
    if (!stack_id.is_valid()) {
      return nullptr;
    }
    const auto stack = stacks_.find(stack_id.value());
    if (stack == stacks_.end()) {
      throw TraceAnalysisError{"event references metadata missing from the scanned trace"};
    }
    return &stack->second;
  }

  OfflineSymbolizer symbolizer_;
  noleax::trace::FileHeader file_header_;
  std::unordered_map<std::uint64_t, ModuleEntry> modules_;
  std::unordered_map<std::uint64_t, noleax::trace::StackDefinition> stacks_;
  bool scanned_{false};
  bool trim_agent_frames_{false};
};

TraceMetadata::TraceMetadata(const SymbolizerOptions& symbolizer_options)
    : impl_{std::make_unique<Impl>(symbolizer_options)} {}

TraceMetadata::~TraceMetadata() = default;

EventStreamResult TraceMetadata::scan(std::istream& input, EventStreamOptions options) {
  return impl_->scan(input, options);
}

EventMetadata TraceMetadata::metadata(const noleax::trace::Event& event) const {
  return impl_->metadata(event);
}

EventPresentation TraceMetadata::presentation(const noleax::trace::Event& event) const {
  return impl_->presentation(event);
}

void TraceMetadata::set_trim_agent_frames(bool enabled) noexcept {
  impl_->set_trim_agent_frames(enabled);
}

}  // namespace noleax::analyzer
