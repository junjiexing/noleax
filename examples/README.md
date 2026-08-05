# Noleax 配置示例

这些文件展示同一功能的 TOML 写法：

- `run-nt-heap.toml`：启动 x64 目标，只捕获 NT Heap，30 秒后停止捕获。
- `run-custom-hooks.toml`：同上，另把第三方 allocator 的导出函数声明为 custom hook 点。
- `analyze-events.toml`：把成功的 alloc/realloc/free 事件输出为 JSON。
- `analyze-outstanding.toml`：查找 `[0s,900ms)` 创建且 trace 结束时仍存活的 1 KiB 到 1 MiB 对象
  （leaks 模式）。

使用前把 `run-nt-heap.toml` 中的 `application.exe` 和参数改为实际目标。三份文件使用相对路径，所以
`capture.nlx` 和分析输出都位于配置文件所在目录。先验证，再执行：

~~~powershell
noleax.exe --config .\examples\run-nt-heap.toml config validate
noleax.exe --config .\examples\run-nt-heap.toml
noleax.exe --config .\examples\analyze-events.toml
noleax.exe --config .\examples\analyze-outstanding.toml
~~~

命令行覆盖 TOML。例如：

~~~powershell
noleax.exe --config .\examples\analyze-events.toml analyze --format csv --output .\events.csv
~~~

`run` 支持 `remote-thread`、`thread-hijack`、`entrypoint-code` 和 `static-pe-patch` 注入，
`attach` 支持 `remote-thread` 和 `thread-hijack`，并可用 `noleax patch` 生成静态 patch 副本。
完整流程见 [../docs/QUICKSTART.md](../docs/QUICKSTART.md)。

