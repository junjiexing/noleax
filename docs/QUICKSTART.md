# Noleax Windows x64 快速上手

本指南适用于 V1 release candidate。当前支持 Windows x64 控制器与 x64 目标；`run` 支持
`remote-thread`、`thread-hijack`、`entrypoint-code` 和 `static-pe-patch` 注入，`attach` 支持
`remote-thread` 和 `thread-hijack`，并可用 `noleax patch` 生成静态 patch 副本。

## 1. 准备

解压本地 RC ZIP 后进入 `bin`，并保持 `noleax.exe` 与 `noleax-agent.dll` 在同一目录。源码构建方式
见 [../BUILDING.md](../BUILDING.md)。在 PowerShell 中先运行只读检查：

~~~powershell
.\noleax.exe doctor
~~~

需要检查具体目标时可增加 `--target`。输出中的 required check 必须为 `pass`；未提供探针时显示
`skipped` 是正常状态。

~~~powershell
.\noleax.exe doctor --target C:\apps\demo.exe --inject-method remote-thread
~~~

## 2. 启动目标并捕获

下面的命令只 hook Windows NT Heap，并把 trace 限制在 256 MiB。`--` 后的内容原样作为目标程序和
参数传入。

~~~powershell
.\noleax.exe run --hook-profile windows-nt-heap --max-trace-size 256MiB `
  --trace .\capture.nlx -- C:\apps\demo.exe --workload sample
~~~

默认模式（agent 直写）下，注入后 agent 自行记录并直写 trace：`--capture-duration` 由 agent
到点自行收尾，目标继续以未插装状态运行；无 duration 时 agent 在目标退出时完成收尾，正常退出
的 trace 带 end-of-trace。汇总统计从 trace 回读，退出码由 trace 完整性驱动（0 完整、2 不完整）。
Ctrl+C 不再驱动收尾：控制器改为 detached 等待（退出码 2），agent 继续到 duration 或目标退出。
需要实时控制（查询状态、Ctrl+C 驱动 drain）时加 `--live` 恢复管道会话。

默认 profile `windows-native` 同时捕获 NT Heap 与 NT virtual-memory API。只关注 heap 时显式使用
`windows-nt-heap` 可减少事件量和干扰。

## 3. Attach 到运行中的目标

先取得 PID，再以与目标相同权限级别运行 Noleax：

~~~powershell
.\noleax.exe attach --pid 1234 --hook-profile windows-nt-heap `
  --capture-duration 30s --trace .\attach.nlx
~~~

attach 无法知道注入前已经存在的 allocation。生成的分析结果会标记
`preexisting_allocations_unknown`，并以退出码 2 表示范围不完整；这不代表命令崩溃或 trace 不可读。

## 3.1 standalone：无法注入也无法 attach 时

先用 `--standalone` 生成 patched 副本，再把 agent 和配置文件放在副本同目录，直接运行即可，
不需要 noleax 参与启动或连接：

~~~powershell
.\noleax.exe patch --input C:\apps\demo.exe --output .\demo.patched.exe --standalone
Copy-Item .\noleax-agent.dll .\demo-dir\
@'
schema_version = 1

[trace]
path = "demo.nlx"
'@ | Set-Content .\demo-dir\noleax-agent.toml
.\demo-dir\demo.patched.exe
.\noleax.exe analyze .\demo-dir\demo.nlx
~~~

agent 在目标启动时读取配置并自写 trace；正常退出时 trace 完整（含 end-of-trace），也可改用
环境变量 `NOLEAX_AGENT_CONFIG` 指向其他配置路径。完整语义见
[STATIC_PE_PATCH.md](STATIC_PE_PATCH.md) 第 8 节。

## 4. 查看全部事件

console 适合交互查看，JSON/CSV 适合自动处理：

~~~powershell
.\noleax.exe analyze --mode events --format console .\capture.nlx
.\noleax.exe analyze --mode events --format json --output .\events.json .\capture.nlx
.\noleax.exe analyze --mode events --format csv --output .\events.csv .\capture.nlx
~~~

每个事件引用去重后的 stack id，analyzer 会展开为对应调用栈。可按事件、API、线程、大小、模块或
allocation id 过滤。例如：

~~~powershell
.\noleax.exe analyze --mode events --event alloc --api RtlAllocateHeap `
  --min-size 1KiB --max-size 1MiB .\capture.nlx
~~~

## 5. 查找时间窗口内仍存活的 allocation

leaks 模式选择在半开区间 `[from,to)` 内发生的 allocation/reallocation，并只保留到观察点 end 仍
未释放的对象。三个窗口参数全部可选；end 省略或晚于 trace 结束时间时使用 trace 结束时间，to
超过结束时间时按结束时间截断。

~~~powershell
.\noleax.exe analyze --mode leaks --from 0s --to 10s `
  --min-size 1KiB --max-size 1MiB --format json `
  --output .\outstanding.json .\capture.nlx
~~~

省略全部窗口参数时列出整个 trace 中任何时间申请、结束时仍未释放的对象。追加 `--group-by stack`
可按调用栈聚合存活对象：

~~~powershell
.\noleax.exe analyze --mode leaks --group-by stack --sort bytes .\capture.nlx
~~~

这是一份候选集合，不等同于程序语义上的泄漏证明。应重复 workload、缩小时间窗口，并结合调用栈
和目标生命周期判断。

## 6. 使用 TOML

[../examples](../examples) 提供 run、events 和 outstanding 三份配置。功能设置的优先级始终是：

~~~text
built-in defaults < TOML < command line
~~~

先验证配置而不执行目标：

~~~powershell
.\noleax.exe --config .\examples\run-nt-heap.toml config validate
~~~

配置中的 `operation` 可直接选择操作：

~~~powershell
.\noleax.exe --config .\examples\analyze-events.toml
~~~

CLI 可以覆盖配置。例如以下命令保留 TOML 中的其他字段，但改为 CSV 输出：

~~~powershell
.\noleax.exe --config .\examples\analyze-events.toml analyze `
  --format csv --output .\events.csv
~~~

相对路径在 TOML 中相对于配置文件目录，在 CLI 中相对于当前目录。完整字段见
[CONFIG.md](CONFIG.md)，所有选项见 [CLI.md](CLI.md)。

## 7. 结果与退出码

- 0：成功且结果完整。
- 2：操作完成，但 attach blind spot、丢弃记录或可恢复尾部等因素使结果不完整。
- 3：注入、权限或远程初始化失败。
- 4：trace 已损坏或版本不受支持，无法继续。
- 5：平台、架构或方法尚未实现。

不要把退出码 2 当作无输出；先读取输出中的 completeness 原因。遇到问题见
[TROUBLESHOOTING.md](TROUBLESHOOTING.md)。
