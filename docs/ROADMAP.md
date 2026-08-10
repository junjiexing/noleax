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

源码布局与工具链为跨平台预留（配置、analyzer、trace 格式均与平台解耦），但 hook、注入与
控制器只有 Windows x64 实现。Linux x86_64/glibc 端口的开发计划见
[LINUX_PORT_PLAN.md](LINUX_PORT_PLAN.md)（待审核，未开始实施）；macOS 没有支持时间表。
