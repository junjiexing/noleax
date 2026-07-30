# Windows Hook Hardening Gate

> 状态：P4.9 自动化部分完成；Application Verifier/Full Page Heap 提权验收待执行
> 范围：Windows x64 `RtlAllocateHeap` prototype 的 CFG、CET、SEH、Page Heap 和长压力

## 1. Hardened 构建

`windows-x64-hardened` 是独立 Release preset，不改变普通 Debug/Release 产物。它对 Noleax 的 C/C++
目标启用 compiler/linker `/guard:cf`，并为 EXE/DLL 启用 `/CETCOMPAT`。hardened CTest 使用 `dumpbin
/headers` 检查以下五个真实产物同时包含 `Control Flow Guard` 和 `CET compatible`：

- MD/MT heap workload；
- hook harness DLL；
- 并发 quiescence executable；
- `HEAP_GENERATE_EXCEPTIONS` executable。

并发 quiescence 目标还调用 `GetProcessMitigationPolicy`。CFG 是 hardened preset 的硬门禁；CET 的 PE
标记始终是硬门禁，硬件 shadow stack 是否实际启用则由运行机器决定。当前机器同时报告：

~~~text
cfg=1 cet=1 cet_query=1
~~~

## 2. SEH 合同

`RtlAllocateHeap(..., HEAP_GENERATE_EXCEPTIONS, impossible_size)` 会以 SEH 离开 original。普通 C++ RAII
不能作为 `/EHsc` 下异步 SEH 的清理保证，因此 replacement 使用显式 unscoped lifecycle/guard，并在
MSVC `__finally` 中严格反向退出：

1. replacement in-flight 加一并取得路由；
2. record 路径进入固定 TEB guard；
3. original 抛出 SEH 时，第一遍 exception filter 写入异常失败事件并返回
   `EXCEPTION_CONTINUE_SEARCH`；
4. unwind 时 `__finally` 退出 guard，再减少 replacement in-flight；
5. 原异常继续到目标程序自己的 handler，不被 Noleax 吞掉或替换。

异常事件保存原参数和 NTSTATUS，规范化为 failure event，`system_error.domain=ntstatus`。异常派发期间
不再执行栈展开；有请求深度时将 stack 标为 failed，并生成 stack-detail Loss，但 allocation 事件本身
不会丢失。filter 保存并恢复 `LastError`。

隔离进程合同验证基线与 hooked 的 exception code、flags、parameters 和 `LastError` 完全一致；当前
结果均为 `STATUS_NO_MEMORY (0xc0000017)` 和 `LastError=8`。handler 返回后还要求 hook depth 与
replacement in-flight 都为零，异常事件可出队，下一次普通 allocation 仍被归为 outermost，随后可
正常 quiesce/shutdown。writer 的 exception 模式再把该事件写入 `.nlx`，由正式 EventStream 回读并
校验 NTSTATUS、Statistics 和 stack-data Loss。

## 3. Application Verifier 与 Full Page Heap

`scripts/Test-WindowsHookHardening.ps1` 使用系统 `appverif.exe` 的 `Heaps` layer，并显式设置
`Heaps.Full=true`，不依赖工具版本的默认值。该阶段需要 64-bit 管理员 PowerShell，因为 AppVerifier
通过 HKLM Image File Execution Options 配置新进程。脚本会：

1. 拒绝覆盖任一同名 image 已存在的 IFEO 设置；
2. 分别启用 MD、MT、quiescence 和 normal writer 目标；
3. 检查 `GlobalFlag` 包含 `0x02000000`，证明 Full Page Heap 已启用；
4. workload 自身要求 `verifier.dll`/`vrfcore.dll` 已加载，并再次检查进程 global flags；
5. 比较 MD/MT 的 baseline/hooked 摘要，重复 quiescence 和 normal writer；
6. 无论成功或失败都在 `finally` 中先完成全部 AppVerifier 删除，再统一检查 IFEO；若当前版本留下
   零值、零子键的空容器，则只删除已确认由本轮新建的空 key；
7. 同时保留并报告 phase 原始错误和 cleanup 错误，避免清理问题遮蔽根因。

脚本不会覆盖或删除预先存在的 AppVerifier 设置。AppVerifier 日志保留在其系统默认目录，供人工检查。

## 4. 当前自动结果

| 门禁 | 结果 |
|---|---|
| Debug full suite | 178/178 |
| Release full suite | 178/178 |
| Hardened full suite | 183/183 |
| CFG/CET PE metadata | 5/5 images |
| Hardened runtime mitigation | CFG=1, CET=1 |
| Hardened quiescence race | 100/100 |
| Hardened MD/MT 8×20,000×2 ABI 差分 | 3/3 repetitions |
| SEH baseline/hooked/event/finally cleanup | pass |
| Exception trace/EventStream | pass |
| Application Verifier/Full Page Heap | 待管理员终端执行 |

长差分每轮摘要与 P4.8 Release 基线一致：

~~~text
attempts=160024 successes=160000 expected_failures=24 frees=160000
rtl_last_error_changes=8 win32_last_error_changes=8
rtl_last_error_hash=0x2fc65ff63169b923
win32_last_error_hash=0xdb3089d8201ac1a3
checksum=0x7caf2ccfa0606232
~~~

## 5. 运行方法

普通终端可复现全部非提权门禁；`-RequireCetRuntime` 适用于已知支持 CET shadow stack 的机器：

~~~powershell
.\scripts\Test-WindowsHookHardening.ps1 `
  -SkipApplicationVerifier `
  -RequireCetRuntime
~~~

最终 Page Heap 验收必须在 64-bit 管理员 PowerShell 中运行：

~~~powershell
.\scripts\Test-WindowsHookHardening.ps1 -RequireCetRuntime
~~~

若机器不支持 CET runtime enforcement，省略 `-RequireCetRuntime`；PE 的 CFG/CET 标记和 CFG runtime
仍会强制验证，脚本会明确打印 CET 未启用的 warning，不能把该机器计为 CET runtime 覆盖。

在管理员验收通过并 review AppVerifier 日志前，P4.9 不标记完成，`RtlAllocateHeap` profile 继续保持
disabled。
