#pragma once

#include "noleax/agent/windows/rtl_heap_event.hpp"

namespace noleax::agent::windows {

using NtVirtualMemoryEventStatus = RtlHeapEventStatus;
using NtVirtualMemoryEvent = RtlHeapEvent;
using NtVirtualMemoryEventQueue = RtlHeapEventQueue;

}  // namespace noleax::agent::windows
