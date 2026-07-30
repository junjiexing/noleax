# Windows Module Generation Tracking

> 状态：P5.6 Windows x64 完成
> 范围：初始模块快照、loader 通知、ModuleLoad/ModuleUnload、相对栈帧和离线符号化

## 1. 目标

绝对 PC 不能唯一标识长期捕获中的代码。DLL 卸载后，另一代 DLL 可以复用同一地址；如果 stack
dictionary 只比较绝对地址，两代调用栈会被错误合并。P5.6 为每次模块加载分配不复用的
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

## 5. 自动门禁

- codec golden/round-trip、非法 identity/path length；
- EventStream load → unload → 同基址 reload、重复 ID、非法相对帧；
- normalized dictionary 对相同绝对 PC、不同 ModuleId 分配不同 StackId；
- loader notification 初始快照、固定 2-slot queue FIFO 和精确 overflow 计数；
- 真实 DLL load → allocation → unload → 同基址 reload → allocation；
- 两次 allocation 的 module offset/absolute PC 相同但 ModuleId/StackId 不同；
- DLL 已卸载后仍使用 trace identity 完成离线符号化；
- Debug、Release、hardened、CFG/CET 和 Application Verifier/Full Page Heap 回归。

