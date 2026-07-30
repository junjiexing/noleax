# Noleax

Noleax（读音 “no leaks”）是一个基于 hook 的跨平台内存事件捕获和离线分析命令行工具。

当前状态：Windows x64 V1 release candidate 的 AI 技术门禁已完成，正在等待人工最终验收；尚未创建
tag 或发布二进制。`noleax run` 支持 remote-thread、thread-hijack、entrypoint-code 和
static-pe-patch 四种方式并在目标入口前完成注入，`noleax attach` 支持 remote-thread 和
thread-hijack 连接运行中进程，`noleax patch` 可生成静态 patch 副本；Windows NT Heap、virtual
memory 和 native profile 共覆盖九个逻辑 API。trace 使用 Module/Stack 字典去重，`noleax analyze`
已接通 events/outstanding、过滤、console/JSON/CSV 和离线符号解析。

当前与计划能力：

- 使用 `remote-thread`、`thread-hijack`、`entrypoint-code` 或 `static-pe-patch` 启动目标，使用
  `remote-thread` 或 `thread-hijack` attach 到运行中的目标。
- 使用 `noleax patch` 对 PE 副本做静态 patch，并以 `static-pe-patch` 方式捕获。
- 使用 Hoox v0.1.1 hook 规范化内存 API。
- 捕获 alloc、realloc、free、heap lifecycle 和 virtual memory 事件。
- 将原始调用栈写入有界、可恢复的 trace。
- 输出 console、JSON 或 CSV。
- 分析指定 a/b/c 时间窗口内仍未释放的分配。

Windows x64 快速上手见 [docs/QUICKSTART.md](docs/QUICKSTART.md)，常见失败的定位方法见
[docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)，可直接修改的 TOML 位于 [examples](examples)。

RC 范围、最终自动门禁和二进制哈希见
[docs/RELEASE_CANDIDATE.md](docs/RELEASE_CANDIDATE.md)；必须由人工完成的 clean-machine 与发布决策见
[docs/RELEASE_CHECKLIST.md](docs/RELEASE_CHECKLIST.md)。许可证、安全联系方式与签名策略确定之前，
不得公开分发。

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
- docs/TRACE_RECOVERY.md
- SECURITY.md
- docs/SECURITY_AUDIT.md
- docs/QUICKSTART.md
- docs/TROUBLESHOOTING.md
- docs/PACKAGING.md
- docs/RELEASE_CANDIDATE.md
- docs/RELEASE_CHECKLIST.md

## Build

完整、可复现的 Windows x64 CMake/Ninja/vcpkg 命令见 [BUILDING.md](BUILDING.md)。

## License

Noleax 自身许可证尚未确定。在许可证明确及正式发布获批前，不应对外分发。

第三方依赖、版本、Hoox 修改及完整版权文本清单见
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)；六份原始文本会随本地 RC 包提供。
