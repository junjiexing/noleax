#include "noleax/controller/windows/process.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <ios>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "noleax/trace/event.hpp"
#include "noleax/trace/record_codec.hpp"
#include "noleax/trace/trace_writer.hpp"
#include "noleax/trace/wire_format.hpp"
#include "support/json_dom.hpp"

namespace {

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

 private:
  HANDLE value_{nullptr};
};

struct ChildResult {
  std::uint32_t exit_code{0U};
  std::string log;
};

[[nodiscard]] std::string read_file(const std::filesystem::path& path) {
  std::ifstream input{path, std::ios::binary};
  if (!input) {
    throw std::runtime_error{"cannot read recovery test file"};
  }
  std::ostringstream output;
  output << input.rdbuf();
  return output.str();
}

void write_file(const std::filesystem::path& path, std::string_view contents) {
  std::ofstream output{path, std::ios::binary | std::ios::trunc};
  if (!output) {
    throw std::runtime_error{"cannot create recovery test file"};
  }
  output.write(contents.data(), static_cast<std::streamsize>(contents.size()));
  if (!output) {
    throw std::runtime_error{"cannot write recovery test file"};
  }
}

void remove_file(const std::filesystem::path& path) {
  std::error_code error;
  static_cast<void>(std::filesystem::remove(path, error));
  if (error) {
    throw std::runtime_error{"cannot remove stale recovery test file"};
  }
}

[[nodiscard]] std::wstring command_line(const std::filesystem::path& executable,
                                        const std::vector<std::string>& arguments) {
  std::wstring result = noleax::controller::windows::quote_windows_argument(executable.native());
  for (const auto& argument : arguments) {
    result.push_back(L' ');
    result.append(noleax::controller::windows::quote_windows_argument(
        noleax::controller::windows::utf8_to_wide(argument)));
  }
  return result;
}

[[nodiscard]] ChildResult run_child(const std::filesystem::path& executable,
                                    const std::vector<std::string>& arguments,
                                    const std::filesystem::path& log_path) {
  SECURITY_ATTRIBUTES security{};
  security.nLength = sizeof(security);
  security.bInheritHandle = TRUE;
  Handle log{CreateFileW(log_path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, &security, CREATE_ALWAYS,
                         FILE_ATTRIBUTE_NORMAL, nullptr)};
  if (!log.valid()) {
    throw std::runtime_error{"cannot create recovery child log"};
  }
  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  startup.dwFlags = STARTF_USESTDHANDLES;
  startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
  startup.hStdOutput = log.get();
  startup.hStdError = log.get();

  std::wstring text = command_line(executable, arguments);
  std::vector<wchar_t> mutable_text{text.begin(), text.end()};
  mutable_text.push_back(L'\0');
  PROCESS_INFORMATION process{};
  if (CreateProcessW(executable.c_str(), mutable_text.data(), nullptr, nullptr, TRUE,
                     CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT, nullptr, nullptr, &startup,
                     &process) == FALSE) {
    throw std::runtime_error{"cannot start recovery child process"};
  }
  Handle process_handle{process.hProcess};
  Handle thread_handle{process.hThread};
  const DWORD wait = WaitForSingleObject(process_handle.get(), 15'000U);
  if (wait != WAIT_OBJECT_0) {
    static_cast<void>(TerminateProcess(process_handle.get(), 99U));
    throw std::runtime_error{"recovery child process timed out"};
  }
  DWORD exit_code = 0U;
  if (GetExitCodeProcess(process_handle.get(), &exit_code) == FALSE) {
    throw std::runtime_error{"cannot query recovery child exit code"};
  }
  log = Handle{};
  return {exit_code, read_file(log_path)};
}

[[nodiscard]] std::string utf8_path(const std::filesystem::path& path) {
  return noleax::controller::windows::wide_to_utf8(path.native());
}

[[nodiscard]] noleax::trace::FileHeader file_header() {
  noleax::trace::FileHeader header;
  header.pointer_width = 8U;
  header.platform = noleax::trace::Platform::kWindows;
  header.architecture = noleax::trace::Architecture::kX64;
  header.session_id[0] = std::byte{0x52};
  header.monotonic_frequency = 10'000'000U;
  header.monotonic_origin = 10U;
  return header;
}

[[nodiscard]] noleax::trace::Event allocation_event() {
  noleax::trace::Event event;
  event.header.sequence = noleax::trace::Sequence{1U};
  event.header.monotonic_ticks = 20U;
  event.header.thread_id = 7U;
  event.header.api_id = 1U;
  event.header.status = noleax::trace::EventStatus::kSuccess;
  noleax::trace::AllocationEvent allocation;
  allocation.heap_handle = 0x100U;
  allocation.requested_size = 64U;
  allocation.result_address = 0x1000U;
  allocation.allocation_id = noleax::trace::AllocationId{1U};
  event.payload = allocation;
  noleax::trace::validate_event(event);
  return event;
}

void require_written(noleax::trace::TraceWriter& writer,
                     const noleax::trace::ChunkDescriptor& descriptor,
                     const std::vector<std::byte>& payload) {
  if (writer.write_chunk(descriptor, payload) != noleax::trace::ChunkWriteResult::kWritten) {
    throw std::runtime_error{"recovery fixture writer reached its size limit"};
  }
}

[[nodiscard]] std::string valid_trace(bool include_unknown_record) {
  using namespace noleax::trace;
  std::ostringstream output{std::ios::binary};
  TraceWriter writer{output, file_header()};

  std::vector<std::byte> metadata;
  append_capture_scope_record(metadata, CaptureScope{true, false});
  ChunkDescriptor metadata_descriptor;
  metadata_descriptor.type = ChunkType::kMetadata;
  require_written(writer, metadata_descriptor, metadata);

  std::vector<std::byte> events;
  append_event_record(events, allocation_event());
  if (include_unknown_record) {
    append_record(events, 0x7FFFU, 1U, {}, kDefaultMaximumRecordSize);
  }
  ChunkDescriptor event_descriptor;
  event_descriptor.type = ChunkType::kEvent;
  event_descriptor.sequence_begin = Sequence{1U};
  event_descriptor.sequence_end = Sequence{1U};
  require_written(writer, event_descriptor, events);

  EndOfTrace end;
  end.final_sequence = Sequence{1U};
  end.final_monotonic_ticks = 20U;
  end.normal_stop = true;
  end.target_exit_code = 0;
  std::vector<std::byte> end_payload;
  append_end_of_trace_record(end_payload, end);
  ChunkDescriptor end_descriptor;
  end_descriptor.type = ChunkType::kEnd;
  require_written(writer, end_descriptor, end_payload);
  return output.str();
}

void write_u16(std::string& output, std::size_t offset, std::uint16_t value) {
  output.at(offset) = static_cast<char>(value & 0xffU);
  output.at(offset + 1U) = static_cast<char>((value >> 8U) & 0xffU);
}

[[nodiscard]] std::string future_minor_trace() {
  std::string encoded = valid_trace(false);
  write_u16(encoded, 8U, noleax::trace::kFileHeaderSize + 4U);
  write_u16(encoded, 12U, noleax::trace::kTraceFormatMinor + 1U);
  encoded.insert(noleax::trace::kFileHeaderSize, "ext!", 4U);
  return encoded;
}

[[nodiscard]] ChildResult analyze(const std::filesystem::path& noleax,
                                  const std::filesystem::path& trace,
                                  const std::filesystem::path& output,
                                  const std::filesystem::path& log) {
  remove_file(output);
  return run_child(noleax,
                   {"analyze", "--mode", "events", "--format", "json", "--output",
                    utf8_path(output), utf8_path(trace)},
                   log);
}

void verify_recovered_json(const std::filesystem::path& path, bool truncated,
                           bool partially_understood) {
  const auto document = noleax::testing::parse_json(read_file(path));
  const auto& summary = document.at("summary");
  if (document.at("events").array_items().size() != 1U ||
      summary.at("trace_events").unsigned_value() != 1U ||
      summary.at("truncated").boolean_value() != truncated ||
      summary.at("partially_understood").boolean_value() != partially_understood ||
      summary.at("completeness").at("overall").scalar() != "incomplete") {
    throw std::runtime_error{"recovered JSON does not preserve the completed event chunk"};
  }
}

}  // namespace

int main(int argc, char* argv[]) {
  try {
    if (argc != 3) {
      std::cerr << "usage: cli_recovery_test NOLEAX OUTPUT_DIR\n";
      return 2;
    }
    const std::filesystem::path noleax = std::filesystem::absolute(argv[1]);
    const std::filesystem::path output_directory = std::filesystem::absolute(argv[2]);
    static_cast<void>(std::filesystem::create_directories(output_directory));
    const auto log = output_directory / "recovery.log";

    const std::string valid = valid_trace(false);
    write_file(output_directory / "seed.nlx", valid);

    const auto truncated_trace = output_directory / "truncated.nlx";
    const auto truncated_json = output_directory / "truncated.json";
    write_file(truncated_trace, std::string_view{valid}.substr(0U, valid.size() - 1U));
    const ChildResult truncated = analyze(noleax, truncated_trace, truncated_json, log);
    if (truncated.exit_code != 2U) {
      throw std::runtime_error{"truncated trace did not return exit code 2: " + truncated.log};
    }
    verify_recovered_json(truncated_json, true, false);

    const auto unknown_trace = output_directory / "unknown-record.nlx";
    const auto unknown_json = output_directory / "unknown-record.json";
    write_file(unknown_trace, valid_trace(true));
    const ChildResult unknown = analyze(noleax, unknown_trace, unknown_json, log);
    if (unknown.exit_code != 2U) {
      throw std::runtime_error{"unknown record did not return exit code 2: " + unknown.log};
    }
    verify_recovered_json(unknown_json, false, true);

    const auto minor_trace = output_directory / "future-minor.nlx";
    const auto minor_json = output_directory / "future-minor.json";
    write_file(minor_trace, future_minor_trace());
    const ChildResult minor = analyze(noleax, minor_trace, minor_json, log);
    if (minor.exit_code != 2U) {
      throw std::runtime_error{"future minor trace did not return exit code 2: " + minor.log};
    }
    verify_recovered_json(minor_json, false, true);

    std::string corrupt = valid;
    corrupt.back() = static_cast<char>(corrupt.back() ^ 0x01);
    const auto corrupt_trace = output_directory / "corrupt.nlx";
    const auto corrupt_json = output_directory / "corrupt.json";
    write_file(corrupt_trace, corrupt);
    const ChildResult corrupt_result = analyze(noleax, corrupt_trace, corrupt_json, log);
    if (corrupt_result.exit_code != 4U ||
        corrupt_result.log.find("cannot scan input trace") == std::string::npos ||
        read_file(corrupt_json).find("\"completeness\"") != std::string::npos) {
      throw std::runtime_error{"corrupt trace was not rejected as an input error"};
    }

    std::string future_major = valid;
    write_u16(future_major, 10U, noleax::trace::kTraceFormatMajor + 1U);
    const auto major_trace = output_directory / "future-major.nlx";
    const auto major_json = output_directory / "future-major.json";
    write_file(major_trace, future_major);
    const ChildResult major = analyze(noleax, major_trace, major_json, log);
    if (major.exit_code != 4U || major.log.find("cannot scan input trace") == std::string::npos ||
        !read_file(major_json).empty()) {
      throw std::runtime_error{"future major trace was not rejected as incompatible"};
    }

    std::cout << "status=ok truncated=1 corrupt=1 future-minor=1 future-major=1 "
                 "unknown-record=1 retained-events=3 exit-codes=2,4\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "cli recovery test failed: " << error.what() << '\n';
    return 1;
  }
}
