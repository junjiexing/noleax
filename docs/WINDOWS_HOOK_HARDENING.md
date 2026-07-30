# Windows Hook Hardening Gate

> 状态：P5.2 Windows x64 allocate/reallocate/free 自动门禁完成
> 范围：NT Heap 三个 adapter 的 CFG、CET、SEH、fail-fast、Page Heap 和长压力

## 1. Hardened 构建

`windows-x64-hardened` 是独立 Release preset，不改变普通 Debug/Release 产物。它对 Noleax 的 C/C++
目标启用 compiler/linker `/guard:cf`，并为 EXE/DLL 启用 `/CETCOMPAT`。hardened CTest 使用
`dumpbin /headers` 检查以下 10 个真实 PE 同时包含 `Control Flow Guard` 和 `CET compatible`：

- MD/MT heap workload；
- alloc/free 组合 hook harness DLL；
- allocate-only 与 alloc/free 组合 trace writer；
- allocate/free 两个并发 quiescence executable；
- free contract 与 free fail-fast executable；
- allocate exception executable。

两个 quiescence 目标还调用 `GetProcessMitigationPolicy`。CFG 是硬门禁；CET 的 PE 标记始终是硬门禁，
硬件 shadow stack 是否实际启用则由运行机器决定。当前验收机器的 allocate/free 目标均报告：

~~~text
cfg=1 cet=1 cet_query=1
~~~

## 2. ABI、LastError、SEH 与 fail-fast

两个 replacement 都使用精确 NTAPI 签名、固定 TEB guard 和显式 unscoped lifecycle。original 返回后先
保存 LastError，再执行计数、栈捕获和入队，最后恢复 LastError。recursive/internal 调用只透传
original，不进入 trace。

普通 C++ RAII 不能在 `/EHsc` 下作为异步 SEH 的清理保证，因此 replacement 使用嵌套 SEH：

1. 入口增加 replacement in-flight 并取得 `record/original/target` 路由；
2. record 路径进入固定 TEB guard；
3. original 抛出时，第一遍 exception filter 写固定异常事件并返回
   `EXCEPTION_CONTINUE_SEARCH`；
4. unwind 时 `__finally` 退出 guard，再减少 replacement in-flight；
5. 原异常继续到目标程序自己的 handler，不被 Noleax 吞掉或替换。

`RtlAllocateHeap(..., HEAP_GENERATE_EXCEPTIONS, impossible_size)` 的 baseline/hooked exception code、
flags、parameters 和 LastError 完全一致；当前为 `STATUS_NO_MEMORY (0xc0000017)` 和 LastError 8。

`RtlFreeHeap` 普通环境合同覆盖 valid、null address、null heap 和 `flags=0xffffffff`，返回值及
LastError 与 baseline 一致。Application Verifier Full Page Heap 会让最后一例以 `0xc0000005` 离开；
测试允许环境改变原始合同，但要求同一环境中的 baseline/hooked 在 returned/result/exception/LastError
上逐字段一致，并验证 exception event、失败/异常计数以及 `__finally` 清理。bad address、wrong heap、
double free 只能在隔离子进程中执行，三种情况的 baseline/hooked 进程退出码均为
`STATUS_HEAP_CORRUPTION (0xc0000374)`。

异常事件保存原参数和 NTSTATUS，规范化为 failure event。异常派发期间不执行栈展开；请求深度非零时
stack 标为 failed 并生成 stack-detail Loss，但 lifecycle event 本身保留。

## 3. Application Verifier 与 Full Page Heap

`scripts/Test-WindowsHookHardening.ps1` 使用系统 64-bit `appverif.exe` 的 `Heaps` layer，并显式设置
`Heaps.Full=true`。该阶段需要管理员 PowerShell，因为 AppVerifier 通过 HKLM Image File Execution
Options 配置新进程。脚本会：

1. 拒绝覆盖任一同名 image 已存在的 IFEO 设置；
2. 为 MD/MT workload、allocate/free quiescence、allocate-only/组合 writer 和 free contract 共 7 个
   image 启用 verifier；
3. 检查 `GlobalFlag & 0x100` 以及 `PageHeapFlags & 0x1`；
4. workload 自身要求 `verifier.dll`/`vrfcore.dll` 已加载、进程 `NtGlobalFlag` 包含 `0x100`，并从
   64-bit IFEO 再次核对 PageHeapFlags；
5. 重复 baseline/hooked workload、两个 quiescence、两个 writer 和 free contract；
6. 无论成功或失败都在 `finally` 中先删除全部 AppVerifier 设置，再统一检查 IFEO；
7. 只删除 preflight 已证明由本轮创建且清理后为空的 container key，同时保留 phase 和 cleanup 两类
   错误，避免清理问题遮蔽根因。

脚本不会覆盖或删除预先存在的 AppVerifier 设置。Windows 11 Application Verifier 10.0.26100 以
`GlobalFlag=0x100`、`PageHeapFlags=0x3` 表示该组合；GFlags page heap 使用的 `0x02000000` 不能替代
上述判定。

日志保留在 `%USERPROFILE%\AppVerifierLogs`。本轮按每个目标的相对 log index 导出 27 份 XML，全部
只有 logSession，`logEntry` 总数为零。

## 4. 当前自动结果

| 门禁 | 结果 |
|---|---|
| Debug full suite | 182/182 |
| Release full suite | 182/182 |
| Hardened full suite | 192/192 |
| CFG/CET PE metadata | 10/10 images |
| Allocate/free runtime mitigation | CFG=1, CET=1 |
| Allocate/free quiescence race | 各 100/100 |
| Hardened MD/MT 8×20,000×2 ABI 差分 | 3/3 repetitions |
| Allocate/free SEH、LastError、guard cleanup | pass |
| Free fail-fast baseline/hooked | 3/3，均为 0xc0000374 |
| Alloc/free trace、跨线程和 generation | pass |
| Application Verifier/Full Page Heap | 3/3 repetitions pass |
| AppVerifier XML log audit | 27 logs, 0 verifier records |
| IFEO cleanup | 7/7 target keys absent |

长差分每轮摘要保持 P4 基线：

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

完整 Page Heap 门禁必须在 64-bit 管理员 PowerShell 中运行：

~~~powershell
.\scripts\Test-WindowsHookHardening.ps1 -RequireCetRuntime
~~~

已完成构建时可加 `-SkipBuild`。若机器不支持 CET runtime enforcement，省略
`-RequireCetRuntime`；PE 的 CFG/CET 标记和 CFG runtime 仍强制验证，脚本会明确报告 CET warning，
该机器不能计为 CET runtime 覆盖。

2026-07-30 的 P5.1 管理员门禁按默认重复强度通过，27 份对应日志为零 verifier record，清理后 7 个
目标 IFEO key 全部不存在。profile 仍保持 disabled，等待 P5.2 及后续生命周期 API，而不是等待额外
的 P5.1 稳定性门禁。

同日 P5.2 将 `RtlReAllocateHeap`、其 quiescence/contract/SEH 目标加入 hardened registry。Debug 与
Release 各 186/186，hardened 200/200，allocate/reallocate/free 三个 race 各连续 100 次；14 个 PE
通过 CFG/CET metadata 检查。Application Verifier/Full Page Heap 下三轮 workload、三轮 race 及三轮
组合 trace/contract/SEH 均通过，结束后 10 个目标 IFEO key 全部不存在。零大小合同不读取请求大小为
0 的返回块内容，避免测试本身在 Full Page Heap 下越界；该修正后门禁通过。
