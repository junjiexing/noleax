# Noleax 快速上手

本指南适用于 Windows x64 与 Linux x86-64/glibc。Windows 的 `run` 支持
`remote-thread`、`thread-hijack`、`entrypoint-code` 和 `static-pe-patch` 注入，`attach` 支持
`remote-thread` 和 `thread-hijack`，并可用 `noleax patch` 生成静态 patch 副本；Linux 侧
`run` 使用 `ld-preload`、`attach` 使用 `ptrace`（见第 8 节）。

不支持的目标：Protected Process / PPL（部分安全软件、受保护的媒体与服务进程）。Noleax 的
安全模型要求枚举并暂停目标进程的全部线程并读取线程上下文，protected process 会拒绝这些
访问；表现为 hook 安装失败或卸载无法完成（状态保留到进程退出），目标不会崩溃但无法捕获。
跨用户、AppContainer 或更高 integrity 级别的目标同样受权限边界约束，详见
[TROUBLESHOOTING.md](TROUBLESHOOTING.md) 的权限一节。

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

目标进程使用第三方 allocator（jemalloc、mimalloc、自研等）时，默认 profile 只能看到它的大块
VM 申请；把它的分配函数声明为 custom hook 后，逻辑 allocations 与泄露归属会进入同一分析
体系：

~~~powershell
.\noleax.exe run --custom-hook "myalloc.dll:alloc=my_malloc,free=my_free,realloc=my_realloc" `
  --trace .\custom.nlx -- C:\apps\demo.exe
~~~

定位也支持 PDB 符号（`alloc_pdb=myalloc!internal_alloc`）与 RVA（`alloc_rva=0x12340`）；参数
映射、forced 与 wait_module 语义见 [CUSTOM_HOOKS.md](CUSTOM_HOOKS.md)。

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

[../examples](../examples) 提供 run（NT Heap 与 custom hooks 两份）、events 和 outstanding
四份配置。功能设置的优先级始终是：

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

## 8. Linux x86-64

本节适用于 Linux x86-64 控制器与 glibc 目标。分析、过滤、TOML 配置与退出码语义与上文
完全一致，差异集中在注入与 hook profile。保持 `noleax` 与 `noleax-agent.so` 在同一目录。

注入不需要选择方法：`run` 只有 `ld-preload` 一种启动注入（动态加载器在目标入口点之前
加载 agent，时序与 Windows 的入口前注入等价），`attach` 只有 `ptrace`。在 Linux 上指定
Windows 专有方法（`remote-thread`、`thread-hijack`、`entrypoint-code`、`static-pe-patch`）
或 `patch` 命令以退出码 5 拒绝；在 Windows 上指定 `ld-preload`/`ptrace` 同样返回 5。

## 8.1 准备

~~~bash
./noleax doctor --target ./app
~~~

doctor 检查平台架构、agent 可加载性、目标是否为动态链接的 x86-64 ELF（静态目标没有动态
加载器，无法注入，在此明确报错）、setuid/setgid 标记与 ptrace_scope 权限状态。

## 8.2 启动目标并捕获

~~~bash
./noleax run --hook-profile linux-glibc-heap --trace capture.nlx -- ./app --workload sample
~~~

Linux 提供三个 hook profile：

| profile | API 组 |
|---|---|
| linux-glibc-heap | glibc malloc 族（malloc/calloc/realloc/free/posix_memalign/aligned_alloc/memalign/reallocarray） |
| linux-virtual-memory | mmap/munmap/mremap |
| linux-native | 上述两组并集 |

Linux 的默认 profile 是 `linux-glibc-heap`（不同于 Windows 的 `windows-native`）。收尾语义
与 Windows 对齐：无 duration 时 agent 在目标正常退出（`exit`/`_exit` hook）时自行收尾，
正常退出的 trace 带 end-of-trace；`--capture-duration` 到点由控制器驱动停止，目标以
hook 已 revert 的状态继续运行；Ctrl+C 后控制器 detach（退出码 2），agent 继续捕获到目标
退出——注意 detach 之后 duration 定时器不再生效（v1 中它由控制器侧驱动）。profile 的
覆盖边界见 [LINUX_HOOK_PROFILES.md](LINUX_HOOK_PROFILES.md)。

第三方 allocator 的 custom hook 同样可用；Linux 的定位器为 dynsym 导出名、`<role>_sym`
（任意 symtab/dynsym 符号，controller 侧解析）与 `<role>_rva`，`*_pdb` 仅 Windows 可用。
完整语义见 [CUSTOM_HOOKS.md](CUSTOM_HOOKS.md) 与 [CONFIG.md](CONFIG.md)。

## 8.3 Attach 到运行中的目标

~~~bash
./noleax attach --pid 1234 --capture-duration 30s --trace attach.nlx
~~~

attach 固定走 ptrace：缺省方法自动升级为 ptrace，显式指定 `ld-preload` 或 Windows 方法
返回 5。盲期语义与 Windows 相同——attach 无法知道注入前已存在的 allocation，分析结果
标记 `preexisting_allocations_unknown` 并以退出码 2 表示范围不完整；这不代表命令崩溃或
trace 不可读。attach 需要 ptrace 权限：`ptrace_scope=0/1` 时可注入同用户进程，更严格时
需要 `CAP_SYS_PTRACE`，详见 [TROUBLESHOOTING.md](TROUBLESHOOTING.md) 的 Linux 一节。

## 8.4 standalone：不经过控制器直接捕获

Linux 没有 `noleax patch`；standalone 由环境变量直接完成，把 agent 与配置交给动态加载器
即可：

~~~bash
LD_PRELOAD=/path/to/noleax-agent.so NOLEAX_AGENT_CONFIG=cfg.toml ./app
./noleax analyze capture.nlx
~~~

agent 在目标启动时读取 `NOLEAX_AGENT_CONFIG` 指向的捕获 TOML（沿用 `[capture]` 与
`[trace]` 段）并自写 trace；目标正常退出时 trace 完整（含 end-of-trace）。setuid/setgid
目标会忽略 LD_PRELOAD（AT_SECURE 规则），该路径对它们不适用。

分析流程（events/leaks/memory 三种模式、console/JSON/CSV 输出、窗口与聚合过滤）不区分
录制平台，第 4–6 节的示例原样适用。
