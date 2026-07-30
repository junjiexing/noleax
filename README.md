# Noleax

Noleax（读音 “no leaks”）是一个基于 hook 的跨平台内存事件捕获和离线分析命令行工具。

当前状态：Windows x64 的首个端到端工作流已经完成。`noleax run` 可 suspended launch 并在目标入口
前完成注入，`noleax attach` 可连接运行中进程；Windows NT Heap、virtual memory 和 native profile
共覆盖九个逻辑 API。trace 使用 Module/Stack 字典去重，`noleax analyze` 已接通 events/outstanding、
过滤、console/JSON/CSV 和离线符号解析。P7 的高级注入与静态 PE patch 尚未开始。

当前与计划能力：

- 启动目标、attach 和静态 patch 注入。
- 使用 Hoox v0.1.1 hook 规范化内存 API。
- 捕获 alloc、realloc、free、heap lifecycle 和 virtual memory 事件。
- 将原始调用栈写入有界、可恢复的 trace。
- 输出 console、JSON 或 CSV。
- 分析指定 a/b/c 时间窗口内仍未释放的分配。

开发计划和已冻结的设计位于：

- docs/DEVELOPMENT_PLAN.md
- docs/CLI.md
- docs/CONFIG.md
- docs/TRACE_FORMAT.md
- docs/CONSOLE_OUTPUT.md
- docs/JSON_OUTPUT.md
- docs/CSV_OUTPUT.md
- docs/SYMBOLIZATION.md
- docs/RTL_HEAP_BASELINE.md
- docs/RTL_ALLOCATE_HEAP_HOOK.md
- docs/HOOK_GUARD.md
- docs/EVENT_QUEUE.md
- docs/HOOK_BACKEND.md
- docs/HOOK_API_MATRIX.md
- docs/HOOK_BACKEND_AUDIT.md
- docs/SOAK_TESTING.md
- docs/PERFORMANCE.md

## Build

完整、可复现的 Windows x64 CMake/Ninja/vcpkg 命令见 [BUILDING.md](BUILDING.md)。

## License

Noleax 自身许可证尚未确定。在许可证明确及正式发布获批前，不应对外分发。

第三方依赖使用各自许可证；Hoox 的 COPYING 和 NOTICE 将随发布包提供。
