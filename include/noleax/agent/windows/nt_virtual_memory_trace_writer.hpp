#pragma once

#include "noleax/agent/windows/rtl_allocate_heap_trace_writer.hpp"

namespace noleax::agent::windows {

using NtVirtualMemoryTraceWriterOptions = RtlAllocateHeapTraceWriterOptions;
using NtVirtualMemoryTraceWriterStatus = RtlAllocateHeapTraceWriterStatus;
using NtVirtualMemoryTraceWriterResult = RtlAllocateHeapTraceWriterResult;
using NtVirtualMemoryTraceWriter = RtlAllocateHeapTraceWriter;

}  // namespace noleax::agent::windows
