# Thread Hijack 注入
> 注入方式：`thread-hijack`，`run` 与 `attach` 均支持

## 1. 目的与适用范围

`thread-hijack` 把目标进程中一条已有线程的执行流临时重定向到注入 stub，由 stub 完成
`LdrLoadDll(agent)` 与 `noleax_agent_bootstrap`，再把线程还原到被劫持点，使其完全不知情的继续
执行。它不创建远程线程，适用于 `CreateRemoteThread` 被 EDR/策略拦截或审计的环境。

公开入口为 `noleax/controller/windows/thread_hijack_injector.hpp` 的 `ThreadHijack`，生命周期
分三个阶段：

1. 构造（prepare）：解析地址、选择并挂起线程、保存完整线程上下文、写入 stub 并重定向 RIP。
2. `start()`：恢复线程，使其进入 stub。
3. `finish(timeout)`：等待 stub 完成、校验结果、恢复原始上下文并释放远程内存；无论成功、
   stub 报错还是超时，线程上下文都会被恢复。

`abort()` 覆盖握手失败等中途放弃路径，同样恢复线程上下文。

## 2. 上下文保存与恢复（为什么用控制器恢复而不是 stub 自恢复）

stub 运行期间允许破坏全部寄存器：完成后控制器重新挂起线程，并用最初保存的完整
`CONTEXT`（`CONTEXT_FULL | CONTEXT_FLOATING_POINT`，含全部 GP 寄存器、段寄存器、EFlags、
XMM0-15 与 MXCSR）执行 `SetThreadContext` 恢复。

选择控制器恢复而不是 stub 手写恢复的原因：

- 手写 `jmp` 回到任意被劫持 RIP 是间接跳转。在 CET/IBT 强制生效的进程里，任意中间位置没有
  `endbr64`，跳回必然触发 control-protection 异常；`push + ret` 又会撞上 shadow stack 校验。
  `SetThreadContext` 是内核态上下文切换，对 IBT 和 shadow stack 都合法。
- stub 可以因此任意使用寄存器与栈（`and rsp,-16` 强制对齐后直接使用被劫持线程自己的栈），
  不需要逐寄存器保存现场，stub 更短、可审计性更强。

已接受的限制：恢复范围为 `CONTEXT` 覆盖的寄存器，不含 XSTATE（YMM/ZMM 高位）。x64 Windows
ABI 中全部 YMM/ZMM 高位都是易失寄存器，但理论上线程可能恰好停在 AVX 循环中段。V1 文档化该
限制；测试目标以 XMM6-15（非易失）与 GP 非易失寄存器哨兵验证恢复正确性。

## 3. 线程选择（attach）

attach 模式没有现成主线程可用，选择规则（`classify_rip` + 评分）：

- 候选线程必须位于 `MEM_IMAGE` 提交内存内（拒绝 JIT/私有内存中的 RIP）。
- ntdll 帧只接受 RIP 紧邻 `syscall` 指令（前 0x18 字节窗口内存在 `0F 05`）的线程：这是典型的
  阻塞在 `Nt*` 调用的状态，此时线程不持有任何用户态锁。
- ntdll 内部其它帧（堆、loader、字符串辅助函数）一律拒绝：此时线程可能持有进程堆锁或
  loader 锁，stub 里的 `LdrLoadDll`/CRT 初始化会递归进入同一堆管理器，造成堆损坏或死锁。
  这也是初版实现的真实事故：`GetMappedFileNameW` 命名识别失效导致堆管理器内部帧被误判为
  “应用帧”，劫持后主线程在 `RtlpAllocateHeapInternal` 中段被重定向，stub 分配同一堆直接
  使进程以 `0xC0000005` 崩溃。现在分类完全基于 `VirtualQueryEx` 的 `AllocationBase` 与
  ntdll/kernel32/kernelbase 模块基址比较，不依赖模块名解析。
- 评分：应用/其它镜像帧（0）优于 kernel32/kernelbase（1）优于 ntdll syscall 帧（2）；不可用的
  线程直接跳过。找到 0 分线程即止。

stub 不触碰其它线程，交叉锁等待会随其它线程继续运行而自然解除；超时（默认注入超时）后
控制器恢复线程并报错，目标不受影响。

## 4. launch 模式

`run` 使用 `CREATE_SUSPENDED` 的主线程作为劫持对象：此时主线程停在
`ntdll!RtlUserThreadStart`，无锁、无争用，是确定的安全点。stub 带 `wait_for_ready` 标志，
bootstrap 后轮询 `noleax_agent_capture_is_ready`，直到控制器完成 StartCapture 握手才发出
完成信号；控制器随后恢复主线程的原始上下文，进程从 `RtlUserThreadStart` 正常启动。因此
hook 安装严格先于目标 `main`（同 `remote-thread` 语义），`CaptureScope` 仍为
`started_at_process_start=true`。

## 5. stub 参考实现

stub 为 164 字节 x64 机器码（`thread_hijack_injector.cpp` 内嵌字节数组），参考汇编源（ml64
可汇编，字节序列与该源反汇编一致）：

```asm
; rcx = HijackStubData（布局见实现文件 static_assert）
; 阶段语义：stage 1=LdrLoadDll 返回，2=bootstrap 返回，3=capture ready，4=ready 等待超时
mov     r12, rcx
mov     r13, rsp
and     rsp, -16
sub     rsp, 60h
xor     ecx, ecx
xor     edx, edx
lea     r8, [r12+10h]          ; &UNICODE_STRING(agent path)
lea     r9, [r12+20h]          ; &module handle
call    qword ptr [r12+8]      ; LdrLoadDll
mov     [r12+44h], eax
mov     dword ptr [r12+40h], 1
test    eax, eax
js      done
mov     rax, [r12+20h]
test    rax, rax
jz      done
lea     rcx, [r12+50h]         ; &BootstrapParameters
mov     rdx, [r12+28h]
add     rdx, rax               ; module + bootstrap RVA
call    rdx
mov     [r12+48h], eax
mov     dword ptr [r12+40h], 2
test    eax, eax
jnz     done
test    byte ptr [r12+38h], 1  ; wait_for_ready
jz      ready_ok
mov     r13d, 8000000h         ; 有界 ready 轮询
mov     rbx, [r12+20h]
add     rbx, [r12+30h]         ; module + ready RVA
poll:
call    rbx
test    al, al
jnz     ready_ok
pause
dec     r13d
jnz     poll
mov     dword ptr [r12+40h], 4
jmp     done
ready_ok:
mov     dword ptr [r12+40h], 3
done:
mov     dword ptr [r12+4Ch], 1
spin:
pause
jmp     spin                   ; 停在此循环，等待控制器恢复上下文
```

控制器在轮询 done 标志的同时检查线程退出码：线程在 stub 内死亡（例如 stub 崩溃）会立即
终止等待并进入恢复路径，不会空等到超时。

## 6. 失败与回滚语义

- prepare 阶段任何失败都发生在接触线程之前（地址解析、导出检查、模块重名检查），目标不受
  影响。
- stub 报告 `LdrLoadDll` NTSTATUS、bootstrap 结果码或 ready 超时（stage 1/2/4）时，
  `finish()` 恢复线程上下文后抛出带原始状态码的 `InjectionError`。
- done 等待超时：恢复线程上下文；若 stub 尚未调用 bootstrap（stage ≤ 1 且模块句柄有效），
  用 `LdrUnloadDll` 远程卸载 agent（无 worker 竞争）；stage ≥ 2 时 worker 可能已存在，不卸载，
  错误信息保持可见。
- launch 失败沿用既有语义：终止 suspended 目标进程。attach 失败不终止目标。

## 7. 测试

- `controller.thread-hijack-launch`：hijack 启动 suspended 目标，验证 ready 先于 `main`、
  事件守恒、finalized 与 trace 回读。
- `controller.thread-hijack-attach`：
  - 基线与劫持运行的寄存器工作负载 digest 逐字节一致。工作负载（
    `tests/targets/register_workload_target.cpp` + `register_workload.asm`）在四个线程的
    非易失 GP 寄存器（rbx/rbp/rdi/rsi/r15）和 XMM6-15 中放置哨兵并逐迭代校验，任何
    上下文破坏都会改变 digest；目标还有未处理异常上报辅助（写 `.crash` 文件）。
  - hijack attach 产生合法 trace，且 `preexisting_allocations_unknown=true`。
  - 缺少 bootstrap 导出的 agent 镜像在接触线程前被拒绝。
  - 不可达 pipe 强制 stub ready 超时，`finish()` 恢复线程，目标 digest 仍与基线一致。
- CLI e2e 覆盖 `run --inject-method thread-hijack`。
- doctor 将 `remote-thread`/`thread-hijack`/`entrypoint-code` 报告为支持。

## 8. 已知限制

- 不保存/恢复 XSTATE（YMM/ZMM 高位）；线程恰好停在 AVX-256/512 循环中段时理论上有状态
  损坏风险。AVX 敏感场景建议使用 `remote-thread`。
- 全部线程都停在 ntdll 非 syscall 帧（极端罕见的全堆操作瞬间）时选择失败并报错，不会劫持
  危险线程。
- attach 模式下 agent 若已开始 bootstrap 后控制器消失，agent 保持加载但处于未初始化状态
  （与其它注入方式一致）。
- 被劫持线程在 stub 内运行的时间通常为毫秒级；在此期间该线程不执行应用代码。
