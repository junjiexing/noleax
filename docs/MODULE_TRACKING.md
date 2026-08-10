# Windows Module Generation Tracking

> 范围：初始模块快照、loader 通知、ModuleLoad/ModuleUnload、相对栈帧和离线符号化

## 1. 目标

绝对 PC 不能唯一标识长期捕获中的代码。DLL 卸载后，另一代 DLL 可以复用同一地址；如果 stack
dictionary 只比较绝对地址，两代调用栈会被错误合并。模块跟踪为每次模块加载分配不复用的
`ModuleId`，并把栈帧规范化为：

~~~text
(module_id, module_offset, absolute_address, flags)
~~~

绝对地址始终保留，用于诊断和没有模块信息时的回退；`module_id + module_offset` 提供历史代次语义。

## 2. 捕获模型

writer 在安装内存 hook 前创建 `WindowsModuleTracker`：

1. 先通过 `LdrRegisterDllNotification` 注册 load/unload 通知。
2. 再用当前进程模块枚举建立初始快照，避免注册与枚举之间出现盲区。
3. 初始模块的 load tick 使用 trace monotonic origin。
4. 注册后、枚举中加载的模块可能同时出现在快照和通知中；writer 只把相同 live base/size 的第一次
   通知视为快照确认，不创建伪代次。
5. 每个真实 unload 结束当前代次；同一路径、同一基址重新 load 仍取得新的 `ModuleId`。

loader callback 进入固定 TEB `InternalThreadScope`，保存和恢复 `LastError`，只执行有界操作：

- 复制固定上限的 UTF-16 image path；
- 复制 base 和 image size；
- 用 `ReadProcessMemory` 快照 PE timestamp/checksum；
- 可用时复制 RSDS GUID、age 和固定上限的 PDB path；
- 写入预分配的 bounded MPSC queue。

callback 不创建字符串、不解析 PDB、不访问符号服务器、不写 trace，也不等待用户态锁。路径超过固定
上限时保留前缀并在 ModuleLoad flags 中显式标记。queue 满时增加独立 drop counter；writer 写出
`queue_full` Loss，trace completeness 因而不会声称完整。

## 3. Writer 顺序

模块通知和内存事件使用同一 QPC 时钟。writer 在处理某个内存事件前，先应用 tick 不晚于该事件的
module 通知；模块状态变化前会先 flush 已经规范化的旧事件。写盘顺序为：

~~~text
CaptureScope -> ModuleLoad/Unload -> StackDefinition -> Event -> Statistics -> EndOfTrace
~~~

Module chunk 必须先于引用新 `ModuleId` 的 StackDefinition。模块通知 tick 也计入 EndOfTrace 的最终
monotonic bound。

成功捕获的栈先按当时 live module range 生成定长 `NormalizedStack`。后台 dictionary 的 hash 和完整
碰撞比较都包含 module generation、offset、绝对地址、flags、capture status 和帧数。dictionary
segment reset 仍只清理内存索引，`StackId` 不复用。

## 4. Trace 与 analyzer 合同

ModuleLoad 保存 `ModuleId`、tick、base、size、UTF-8 image path、PE identity，以及可选 CodeView/PDB
identity。ModuleUnload 保存 `ModuleId` 和 tick。正式 EventStream 校验：

- `ModuleId` 全局唯一；
- unload 只能引用 live generation；
- 同时 live 的模块范围不能重叠；
- module tick 不早于 trace origin 且不倒退；
- 相对栈帧只能引用已定义的历史 generation；
- `absolute_address == module.base + module_offset`，且 offset 在 image range 内。

模块卸载不会删除 analyzer 中的历史 ModuleLoad，因此离线 symbolizer 仍可用 trace 保存的 image/PDB
identity 解析旧 generation。

## 5. 自动验证

- codec golden/round-trip、非法 identity/path length；
- EventStream load → unload → 同基址 reload、重复 ID、非法相对帧；
- normalized dictionary 对相同绝对 PC、不同 ModuleId 分配不同 StackId；
- loader notification 初始快照、固定 2-slot queue FIFO 和精确 overflow 计数；
- 真实 DLL load → allocation → unload → 同基址 reload → allocation；
- 两次 allocation 的 module offset/absolute PC 相同但 ModuleId/StackId 不同；
- DLL 已卸载后仍使用 trace identity 完成离线符号化；
- Debug、Release、hardened、CFG/CET 和 Application Verifier/Full Page Heap 回归。


## 6. Linux 实现：轮询代际

> 状态：已实现（Linux 移植 M2）。`LinuxModuleTracker`（`agent/linux/module_tracker.cpp`）。

Linux 没有进程内模块加载通知（`r_debug` 是调试器接口，不在进程内使用），按移植计划
§5.7 采用轮询模型：

- 初始快照：`dl_iterate_phdr` 全量枚举（构造时完成，打 `kInitialSnapshot`，ticks 取
  monotonic origin），模块边界为 PT_LOAD 段相对 load bias 的覆盖区间；主可执行文件
  路径取 `/proc/self/exe`。
- 变更检测：writer 线程在 drain 循环里调用 `poll()`，重新枚举并与存活集合按 base 比较
  得出 load/unload；同 base 不同内容（尺寸或路径变化）按 unload+load 两个代际处理，
  对应 dlclose 后地址复用。轮询窗口内的多次加载/卸载合并为一批——代际模型天然容忍，
  窗口语义即"相邻两次 poll 之间"。
- 队列纪律与 Windows 相同：有界队列（默认 256），溢出计数丢弃并在 Loss 记录中归因；
  poll 内部任何分配失败按跳过一轮并计入丢弃处理，不终结捕获。
- 与 Windows 通知模型的语义差：通知模型是"事件发生时入队"，轮询模型是"窗口合并入队"；
  两者都满足 writer 的"模块记录先于引用它的事件"排序要求（writer 按 ticks 排水）。
- 身份字段：本期记录不带 ELF build-id（线格式把模块身份设计为可选）；build-id 的落位
  是 M5 的格式治理决策。
