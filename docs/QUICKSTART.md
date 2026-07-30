# Noleax Windows x64 快速上手

本指南适用于 V1 release candidate。当前支持 Windows x64 控制器、x64 目标和
`remote-thread` 注入；P7 的 thread hijack、entrypoint 注入和静态 PE patch 已延期。

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

目标退出、达到 `--capture-duration` 或按 Ctrl+C 时，Noleax 会停止捕获、drain writer 并输出统计。
达到 duration 或 Ctrl+C 不会终止仍在运行的目标。先用短时、可重复 workload 建立未注入基线，再对
长期进程使用 attach。

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

outstanding 模式选择在半开区间 `[a,b)` 内发生的 allocation/reallocation，并只保留到时间点 c 仍未
释放的对象。省略 c，或 c 晚于 trace 结束时间时，使用 trace 结束时间。

~~~powershell
.\noleax.exe analyze --mode outstanding --a 0s --b 10s `
  --min-size 1KiB --max-size 1MiB --format json `
  --output .\outstanding.json .\capture.nlx
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
