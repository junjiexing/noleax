# Noleax

Noleax（读音 “no leaks”）是一个基于 hook 的跨平台内存事件捕获和离线分析命令行工具。

当前状态：早期开发，首先实现 Windows x64；离线分析器已完成 console、流式 JSON 和 CSV 库输出。

计划能力：

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
- docs/HOOK_API_MATRIX.md
- docs/HOOK_BACKEND_AUDIT.md

## Build

Windows x64 工程骨架已经完成，当前进入可移植核心开发。完整、可复现的 CMake/Ninja/vcpkg 命令见 [BUILDING.md](BUILDING.md)。

## License

Noleax 自身许可证尚未确定。在许可证明确及正式发布获批前，不应对外分发。

第三方依赖使用各自许可证；Hoox 的 COPYING 和 NOTICE 将随发布包提供。
