# 尚未完成的能力

Noleax 当前版本的已知边界。这里只列**未实现**的能力；已实现功能见 [CLI.md](CLI.md) 与
[QUICKSTART.md](QUICKSTART.md)。

## trace 文件轮转

`trace.on_full = "rotate"` 与 `trace.max_files > 1` 尚未实现：达到单文件上限时以退出码 5
拒绝，不会静默降级。跨文件的 sequence、module generation 与机器输出 schema 尚未定稿，因此
`analyze` 每次也只接受一个 trace，跨文件分析随轮转一并提供。

## attach 注入方法限制

`entrypoint-code` 不适用于 attach（目标主线程上下文不可恢复）。

## 其他平台

Linux x86-64/glibc 端口已完成（实现与历程见 [LINUX_PORT_PLAN.md](LINUX_PORT_PLAN.md)）：
run/attach/analyze/symbols/config/doctor 全命令可用，hook profile 覆盖 glibc malloc 族与
mmap 族，自定义 hook 与 standalone 模式齐备。

本期明确不做、可作为后续立项的边界：

- **musl libc 与 ARM64**：hook 目标集、栈捕获与重定位都按 glibc/x86-64 验证过；musl 的
  分配器实现不同，ARM64 需要 hoox 的 aarch64 路径与新的 rendezvous/上下文处理。
- **`noleax patch` 的 ELF 静态补丁**：Linux 的 standalone 由 `LD_PRELOAD` +
  `NOLEAX_AGENT_CONFIG` 覆盖；确有"无法改环境变量"的硬需求时再立项（DT_NEEDED 注入）。
- **macOS**：没有支持时间表。
- **trace 文件轮转**与 Windows 侧共用，见上节。
