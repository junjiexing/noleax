# 尚未完成的能力

Noleax 当前版本的已知边界。这里只列**未实现**的能力；已实现功能见 [CLI.md](CLI.md) 与
[QUICKSTART.md](QUICKSTART.md)。

## trace 文件轮转

`trace.on_full = "rotate"` 与 `trace.max_files > 1` 尚未实现：达到单文件上限时以退出码 5
拒绝，不会静默降级。跨文件的 sequence、module generation 与机器输出 schema 尚未定稿，因此
`analyze` 每次也只接受一个 trace，跨文件分析随轮转一并提供。

## attach 时卸载 agent

`--unload-on-stop` 目前只接受 `false`：捕获结束后 agent 不会从运行中的目标卸载。
`entrypoint-code` 不适用于 attach（目标主线程上下文不可恢复）。

## 分析窗口表达式

`--from/--to/--end` 只接受相对 trace 起点的时间值，不支持 sequence 表达式（例如
`#123456`）。时间超过 trace 终点时按终点截断。

## 其他平台

源码布局与工具链为跨平台预留（配置、analyzer、trace 格式均与平台解耦），但 hook、注入与
控制器只有 Windows x64 实现。Linux/macOS 没有支持时间表。
