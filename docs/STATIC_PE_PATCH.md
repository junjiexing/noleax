# Static PE Patch

> 命令：`noleax patch`；捕获：`noleax run --inject-method static-pe-patch`

## 1. 目的与边界

static PE patch 把一份原生 x64 EXE **的副本**改写为自插装镜像：新增一个 `.nlxboot` section
存放 bootstrap stub 与数据，并把原入口点（保留可能的 `endbr64`）的前 5 字节改为直接
`jmp rel32` 跳转到 stub。**`AddressOfEntryPoint` 保持不变**：直接跳转不需要 CFG 目标也不需要
`endbr64`，入口 RVA 不变使 loader 的 CFG 校验与 IBT 落点继续合法，且补丁在 ASLR 下天然成立。
stub 完成 agent 加载与会话握手后，把入口点原始字节写回内存映像、刷新指令缓存并跳回原
入口。输入文件永不被修改；输出总是新文件，且先写临时文件、重新解析验证通过后才改名。

V1 边界（与计划 §15.7 一致）：

- 只接受 AMD64 PE32+ EXE；拒绝 DLL、驱动、EFI、managed（CLR header 非空）、结构异常或
  packed（UPX section 名、入口 section 无原始数据、入口点不在任何 section 内）镜像。
- Authenticode 签名文件默认拒绝；`--allow-break-signature` 时才继续，并把签名 overlay 从输出
  中剥离（签名目录清零）。签名不是唯一 overlay 时拒绝。
- 非签名的多余 overlay 拒绝；不支持已加壳程序的通用 patch。
- 节表必须还有空位容纳一个新 section header，否则拒绝。
- 已打过补丁的镜像（已含 `.nlxboot`）拒绝再次 patch。
- 入口点到新 section 的距离必须落在 rel32 范围内（常规 EXE 远小于 2 GiB）。

## 2. 补丁布局

`.nlxboot` section（`IMAGE_SCN_CNT_CODE | CNT_INITIALIZED_DATA | MEM_EXECUTE | MEM_READ |
MEM_WRITE`）从偏移 0 开始：

| 偏移 | 内容 |
|---|---|
| 0x000 | bootstrap stub（1203 字节，见第 3 节） |
| 0x500 | `BootstrapParameters`（0x120 字节；全零 = 捕获关闭） |
| 0x620 | marker `NLXPATCH01`（0x0A 字节，patch/run 双向验证） |
| 0x630 | agent 文件名（wchar，NUL 结尾，容量 0x80） |
| 0x6B0 | `noleax_agent_bootstrap`（ascii，容量 0x40） |
| 0x6F0 | `noleax_agent_capture_is_ready`（ascii，容量 0x40） |
| 0x730 | kernelbase/ntdll 模块名与五个导出的 ror13 哈希（各 4 字节） |
| 0x74C | stub 结果码（0 ok、1 disabled、2 无 kernelbase、3 解析失败、4 LoadLibrary 失败、5 导出缺失、6 bootstrap 错误、7 ready 超时） |
| 0x750 | 入口点原始字节（5 字节使用，8 保留） |
| 0x758 | 入口页原始保护属性（8） |
| 0x760 | NtFlushInstructionCache 指针槽（8） |
| 0x768 | 被补丁入口 RVA（8） |
| 0x770 | 寄存器暂存（xmm0-15 + mxcsr + 槽位，0x118 字节） |

section 的 VA 取 `align_up(全镜像最大 section 末尾, SectionAlignment)`，raw 追加在
`align_up(文件尾, FileAlignment)`；`SizeOfImage` 相应增大，`CheckSum` 清零。stub 内两个
imm32 由 patcher 按本文件填写：section RVA（偏移 733）与原入口 RVA（偏移 1041）。

## 3. stub 参考实现

stub 完全位置无关：不改导入表、不加重定位，经 PEB 模块链按 BaseDllName 的 ror13 哈希找到
`kernelbase.dll` 与 `ntdll.dll`，再遍历导出表解析 `VirtualProtect`、
`NtFlushInstructionCache`（恢复入口必需，先于参数检查解析）以及 `LoadLibraryW`、
`GetProcAddress`、`Sleep`。随后：参数为零 → 直接恢复入口字节并跳回原入口；否则
`LoadLibrary(agent)` → bootstrap → 有界轮询 ready（1000×10ms）→ 恢复入口字节并跳回。
恢复序列：`VirtualProtect(RWX)` → 5 字节写回 → 恢复原保护 → `NtFlushInstructionCache`。
寄存器逐项恢复（rax 借用为最终跳转寄存器），最终 `jmp` 到 `image_base + 原入口 RVA`——
函数起点，CET/IBT 与 shadow stack 合法。恢复所需的两个导出无法解析的灾难路径只记录结果码
并驻留（不跳回），绝不以损坏入口继续。

关键流程（完整 ml64 源随实现存档，字节模板与布局由单元测试锁定）：

```asm
lea     r12, section_anchor      ; RIP 相对定位 section 基址
section_anchor:
sub     r12, 7
; ... 保存全部 GP/XMM/mxcsr 到暂存区 ...
; PEB 遍历：一次循环按哈希同时找 kernelbase 与 ntdll
; 先解析 VirtualProtect + NtFlushInstructionCache（恢复必需）
; 参数校验 -> LoadLibraryW/GetProcAddress/Sleep -> agent bootstrap -> ready 轮询
mov     rbx, r12
sub     rbx, <section RVA>       ; FIXUP imm32 -> image base
; VirtualProtect -> rep movsb 写回 5 字节 -> 恢复保护 -> NtFlushInstructionCache
mov     rax, rbx
add     rax, <原入口 RVA>        ; FIXUP imm32
xchg    rax, [r14+112]           ; 借保存的 rax 槽作为最终跳转目标
mov     rsp, r14
; ... 恢复寄存器 ...
jmp     rax
```

历史缺陷记录：v1 方案把 `AddressOfEntryPoint` 指向新 section，loader 的间接入口调用在
`/guard:cf` 目标的 CFG 位图中找不到新入口，hardened preset 下以 `0xC0000409` fail-fast；
改为“入口 RVA 不变 + 直接 rel32 跳转 + stub 运行时写回原始字节”后通过 hardened 验证。

## 4. 捕获流程（run + static-pe-patch）

1. `noleax patch` 生成副本并重新解析验证（默认 `--verify`，可 `--no-verify` 关闭）。
2. `noleax run --inject-method static-pe-patch -- app-patched.exe`：控制器先校验目标确为
   patch 产物（`read_static_patch_info`：section、marker、入口 E9 跳转一致），否则在执行前
   以退出码 1 拒绝。
3. 控制器 suspended 创建进程，定位主镜像基址，把本会话 `BootstrapParameters` 写入
   `image_base + section RVA + 0x500` 的内存映像参数区，恢复主线程。
4. stub 完成加载与握手，agent ready 后才跳回原入口，`started_at_process_start=true` 语义
   与其它 launch 方法一致。
5. agent DLL 以裸文件名（`--agent-name`，默认 `noleax-agent.dll`）经标准 DLL 搜索顺序加载；
   部署时必须把 agent 放在 patched 副本同目录。

## 5. 错误分类与退出码

- 输入结构损坏、截断、非 PE、输出已存在、overlay 异常、无节表空位、agent 名非法、跳转距离
  越界：退出码 1。
- 非 x64、DLL/驱动/EFI、managed、packed、签名未获 `--allow-break-signature`：退出码 5。
- patch 中途失败只删除临时文件，输出路径不产生半成品。

## 6. 测试

- 单元：ror13 哈希参考值锁定（kernelbase、ntdll、LoadLibraryW、GetProcAddress、Sleep、
  VirtualProtect、NtFlushInstructionCache）、stub 布局/fixup 自洽、对真实测试 exe 的
  patch/重解析/info 往返、二次 patch 拒绝、全拒绝矩阵（DLL、managed、x86、EFI、UPX、坏签名、
  截断、入口越界、签名剥离去/不去、overlay、输出已存在、agent 名非法）。
- 集成（`controller.static-pe-patch`）：复制测试目标 → patch → info 校验 → 直接运行
  （参数为零，stub 恢复入口并跳回，目标正常退出）→ `CaptureSession::launch` +
  `kStaticPePatch` 完整捕获（ready 先于 main、finalized、trace 回读）→ 未打补丁目标
  被拒绝。hardened preset 覆盖 `/guard:cf`+`/CETCOMPAT` 目标。
- CLI：`noleax patch` 摘要输出、退出码分类；`run --inject-method static-pe-patch` 端到端。

## 7. 已知限制

- 只支持原生 x64 EXE；不支持 DLL、managed、packed、驱动、EFI。
- 签名在 `--allow-break-signature` 下被剥离，输出不再具有有效 Authenticode 签名。
- 与劫持/入口点方法相同的 XSTATE 限制；stub 运行早于 CRT 初始化，实际无 AVX 状态风险。
- 磁盘上的 patched 副本入口始终保持 E9 跳转；stub 在每次进程启动时于内存中恢复原始字节。
- trace 内不记录 patch 事件本身。

## 8. standalone 独立记录

`noleax patch --standalone` 在 patch 时把 standalone 激活参数烧进 `.nlxboot` 的参数区
（`structure_size`/`version` 不变，`session_token` 为共享 magic 常量，stub 与 ASM 不需要任何
改动）。此后**直接运行 patched 副本**即可自插装：stub 照常加载 agent，agent 识别 magic 后
不连接任何控制器管道，自行读取 TOML 配置并把事件写入 trace。适用于无法由 noleax 启动注入
也无法 attach 的目标。

### 配置发现

1. 环境变量 `NOLEAX_AGENT_CONFIG`（TOML 的完整路径）。
2. 可执行文件同目录的 `noleax-agent.toml`。

两者都没有或配置非法时捕获禁用：目标正常运行、不产出 trace，并向 stderr（有控制台时）与
`OutputDebugString` 输出一行原因。TOML 沿用现有 schema 的 `[capture]` 与 `[trace]` 段
（`hook_profile`、`max_stack_depth`、`min_size`、`path`、`buffer_size`、`max_file_size`、
`flush_interval`、`compression`、`compression_level`），缺省值与 CLI 默认一致；`trace.path`
省略时写到可执行文件同目录的 `<exe 主名>.nlx`。相对 `trace.path` 相对配置文件目录解析。

### custom hook 的烘焙合同

patch 的配置文件（`--config`）声明 `[[custom_hooks]]` 时，`noleax patch` 会在输出副本旁写出
已解析的 `noleax-agent.toml`：PDB 符号（`alloc_pdb` 等）在 patch 时经 DbgHelp 解析为 RVA
并记录模块映像 identity（timestamp/checksum/image size），导出名原样保留。patched 副本运行时
agent 只消费 RVA 与导出名，并在安装前校验记录的映像 identity 与实际加载的模块一致，不一致即
报错而不是错位 hook。运行期 TOML 中出现未解析的 `_pdb` 符号（手写或环境变量指向的配置）时
agent 启动直接报错，提示经 `noleax patch` 烘焙或改用导出符号/RVA，不静默忽略。完整语义见
[CUSTOM_HOOKS.md](CUSTOM_HOOKS.md)。

### 退出收尾

- 正常退出（main 返回、`exit()`、`ExitProcess`）:standalone 模式额外 hook
  `ntdll!RtlExitUserProcess`（forced 重定位），在 writer 后台线程仍存活时完成 quiescence、
  drain 并写出 end-of-trace，trace 完整（`normal_stop=true`）。
- hook 安装失败或直接调用 `TerminateProcess` 时由 `DLL_PROCESS_DETACH` 路径兜底：此时
  writer 线程已被 ExitProcess 杀死，agent 在 loader lock 约束下单线程内联 drain；若线程
  恰好死在写块中途，trace 可能缺少尾记录，analyzer 按可恢复不完整处理（退出码 2），损失
  以 flush interval 为界。
- 崩溃或 `TerminateProcess` 没有任何收尾机会，同样只剩 flush interval 边界内的数据。

### 与管道模式的关系

`run --inject-method static-pe-patch` 启动 standalone 镜像时，控制器仍在进程内存中覆盖
参数区，按普通管道捕获工作；standalone 烘焙只影响"直接运行"的场景。

## 附录 A：stub 完整参考汇编（ml64）

```asm
; P7C static PE patch bootstrap stub (x64, v2). Reference source for the byte
; template used by the static PE patcher.
;
; The patched image keeps its ORIGINAL AddressOfEntryPoint; the first bytes
; after a possible endbr64 are replaced on disk by a direct `jmp rel32` (E9)
; to this stub. A direct branch needs no CFG target and no endbr64, and the
; unchanged entry RVA keeps the loader's CFG check and IBT landing valid.
;
; The stub is fully position independent: it resolves kernelbase.dll and
; ntdll.dll through the PEB loader list, then LoadLibraryW / GetProcAddress /
; Sleep / VirtualProtect / NtFlushInstructionCache through export-hash
; walking, so the patched image needs no import-table or relocation changes.
;
; Data offsets (shared with the C++ layout header, locked by unit tests):
;   [0x500] BootstrapParameters (0x120 bytes, all zero = capture disabled)
;   [0x620] marker "NLXPATCH01" (0x0A bytes)
;   [0x630] agent file name (wchar_t, NUL terminated, capacity 0x80)
;   [0x6B0] "noleax_agent_bootstrap" (ascii, NUL, capacity 0x40)
;   [0x6F0] "noleax_agent_capture_is_ready" (ascii, NUL, capacity 0x40)
;   [0x730] kernelbase.dll name hash (4)
;   [0x734] LoadLibraryW hash (4)
;   [0x738] GetProcAddress hash (4)
;   [0x73C] Sleep hash (4)
;   [0x740] ntdll.dll name hash (4)
;   [0x744] VirtualProtect hash (4)
;   [0x748] NtFlushInstructionCache hash (4)
;   [0x74C] result code out (4): 0 ok, 1 disabled, 2 no kernelbase,
;          3 resolve failed, 4 LoadLibrary failed, 5 export missing,
;          6 bootstrap error, 7 ready timeout
;   [0x750] original entry bytes (5 used, 8 reserved)
;   [0x758] saved page protection (8)
;   [0x760] NtFlushInstructionCache pointer (8)
;   [0x768] patched-entry RVA (8)
;   [0x770] register scratch: xmm0-15 (0x100) + mxcsr (0x10) + slots (0x18)

PARAMS_OFF        EQU 500h
MARKER_OFF        EQU 620h
AGENT_NAME_OFF    EQU 630h
BOOTSTRAP_SYM_OFF EQU 6B0h
READY_SYM_OFF     EQU 6F0h
HASH_KBASE_OFF    EQU 730h
HASH_LOADLIB_OFF  EQU 734h
HASH_GETPROC_OFF  EQU 738h
HASH_SLEEP_OFF    EQU 73Ch
HASH_NTDLL_OFF    EQU 740h
HASH_VP_OFF       EQU 744h
HASH_NTFLUSH_OFF  EQU 748h
RESULT_OFF        EQU 74Ch
ORIG_BYTES_OFF    EQU 750h
OLD_PROTECT_OFF   EQU 758h
NTFLUSH_SLOT_OFF  EQU 760h
PATCH_RVA_OFF     EQU 768h
SCRATCH_OFF       EQU 770h

.code
static_stub proc
    lea     r12, section_anchor              ; RIP-relative: next instruction
section_anchor:
    sub     r12, 7                           ; r12 = section base (stub at 0)
    pushfq
    push    rax
    push    rbx
    push    rcx
    push    rdx
    push    rsi
    push    rdi
    push    rbp
    push    r8
    push    r9
    push    r10
    push    r11
    push    r12
    push    r13
    push    r14
    push    r15
    mov     r14, rsp                         ; pushed-state rsp for the restore
    movdqu  [r12+SCRATCH_OFF+00h], xmm0
    movdqu  [r12+SCRATCH_OFF+10h], xmm1
    movdqu  [r12+SCRATCH_OFF+20h], xmm2
    movdqu  [r12+SCRATCH_OFF+30h], xmm3
    movdqu  [r12+SCRATCH_OFF+40h], xmm4
    movdqu  [r12+SCRATCH_OFF+50h], xmm5
    movdqu  [r12+SCRATCH_OFF+60h], xmm6
    movdqu  [r12+SCRATCH_OFF+70h], xmm7
    movdqu  [r12+SCRATCH_OFF+80h], xmm8
    movdqu  [r12+SCRATCH_OFF+90h], xmm9
    movdqu  [r12+SCRATCH_OFF+0A0h], xmm10
    movdqu  [r12+SCRATCH_OFF+0B0h], xmm11
    movdqu  [r12+SCRATCH_OFF+0C0h], xmm12
    movdqu  [r12+SCRATCH_OFF+0D0h], xmm13
    movdqu  [r12+SCRATCH_OFF+0E0h], xmm14
    movdqu  [r12+SCRATCH_OFF+0F0h], xmm15
    stmxcsr dword ptr [r12+SCRATCH_OFF+100h]
    and     rsp, -16
    sub     rsp, 60h

    ; ---- find kernelbase.dll and ntdll.dll in one loader-list walk ----
    mov     rax, gs:[60h]
    mov     rax, [rax+18h]                   ; PEB->Ldr
    lea     rcx, [rax+10h]                   ; &InLoadOrderModuleList
    mov     rdx, [rcx]                       ; first Flink
    xor     r13d, r13d                       ; kernelbase base
    xor     ebp, ebp                         ; ntdll base
module_walk:
    cmp     rdx, rcx
    je      modules_done
    mov     rsi, [rdx+60h]                   ; BaseDllName.Buffer
    movzx   r8d, word ptr [rdx+58h]          ; BaseDllName.Length
    xor     edi, edi
    shr     r8d, 1
    jz      module_next
name_hash_loop:
    movzx   eax, word ptr [rsi]
    add     rsi, 2
    lea     r9d, [rax-41h]                   ; 'A'
    cmp     r9d, 26
    jae     no_fold
    add     eax, 20h
no_fold:
    ror     edi, 13
    add     edi, eax
    dec     r8d
    jnz     name_hash_loop
module_next:
    cmp     edi, [r12+HASH_KBASE_OFF]
    jne     maybe_ntdll
    mov     r13, [rdx+30h]                   ; DllBase
    jmp     module_advance
maybe_ntdll:
    cmp     edi, [r12+HASH_NTDLL_OFF]
    jne     module_advance
    mov     rbp, [rdx+30h]
module_advance:
    mov     rdx, [rdx]
    test    r13, r13
    jz      module_walk
    test    rbp, rbp
    jz      module_walk
modules_done:
    test    r13, r13
    jz      no_kernelbase
    test    rbp, rbp
    jz      no_kernelbase
    mov     [r12+SCRATCH_OFF+108h], rbp      ; keep ntdll base in the scratch

    ; ---- resolve the two exports the entry restore always needs ----
    mov     rbx, r13
    mov     edi, [r12+HASH_VP_OFF]
    call    resolve_export
    test    rax, rax
    jz      resolve_failed
    mov     [r12+SCRATCH_OFF+110h], rax      ; VirtualProtect
    mov     rbx, rbp
    mov     edi, [r12+HASH_NTFLUSH_OFF]
    call    resolve_export
    test    rax, rax
    jz      resolve_failed
    mov     [r12+NTFLUSH_SLOT_OFF], rax      ; NtFlushInstructionCache

    ; ---- capture stays disabled while the parameters are zeroed ----
    cmp     dword ptr [r12+PARAMS_OFF], 120h
    jne     disabled
    cmp     dword ptr [r12+PARAMS_OFF+4], 1
    jne     disabled
    cmp     word ptr [r12+PARAMS_OFF+8], 0
    je      disabled

    ; ---- resolve the capture exports ----
    mov     rbx, r13
    mov     edi, [r12+HASH_LOADLIB_OFF]
    call    resolve_export
    test    rax, rax
    jz      resolve_failed_capture
    mov     r15, rax                         ; LoadLibraryW
    mov     rbx, r13
    mov     edi, [r12+HASH_GETPROC_OFF]
    call    resolve_export
    test    rax, rax
    jz      resolve_failed_capture
    mov     rbp, rax                         ; GetProcAddress
    mov     rbx, r13
    mov     edi, [r12+HASH_SLEEP_OFF]
    call    resolve_export
    test    rax, rax
    jz      resolve_failed_capture
    mov     r13, rax                         ; Sleep

    ; ---- load the agent ----
    lea     rcx, [r12+AGENT_NAME_OFF]
    call    r15
    test    rax, rax
    jz      load_failed
    mov     r15, rax                         ; agent module

    ; ---- bootstrap and wait for capture readiness ----
    mov     rcx, r15
    lea     rdx, [r12+BOOTSTRAP_SYM_OFF]
    call    rbp
    test    rax, rax
    jz      export_missing
    lea     rcx, [r12+PARAMS_OFF]
    call    rax
    test    eax, eax
    jnz     bootstrap_error
    mov     rcx, r15
    lea     rdx, [r12+READY_SYM_OFF]
    call    rbp
    test    rax, rax
    jz      export_missing
    mov     r15, rax                         ; capture_is_ready
    mov     ebx, 1000                        ; bounded: ~10s of 10ms slices
ready_poll:
    call    r15
    test    al, al
    jnz     ok
    mov     ecx, 10
    call    r13
    dec     ebx
    jnz     ready_poll
    mov     eax, 7
    jmp     set_result
ok:
    xor     eax, eax
    jmp     set_result
disabled:
    mov     eax, 1
    jmp     set_result
no_kernelbase:
    mov     eax, 2
    jmp     set_result_no_restore
resolve_failed:
    mov     eax, 3
    jmp     set_result_no_restore
resolve_failed_capture:
    mov     eax, 3
    jmp     set_result
load_failed:
    mov     eax, 4
    jmp     set_result
export_missing:
    mov     eax, 5
    jmp     set_result
bootstrap_error:
    mov     eax, 6
set_result:
    mov     [r12+RESULT_OFF], eax

    ; ---- restore the original entry bytes (restore-capable paths) ----
    mov     rbx, r12
    sub     rbx, 11111111h                   ; FIXUP: section RVA -> image base
    mov     rbp, rbx
    add     rbp, [r12+PATCH_RVA_OFF]         ; patched entry VA
    mov     rcx, rbp
    mov     edx, 5
    mov     r8d, 40h                         ; PAGE_EXECUTE_READWRITE
    lea     r9, [r12+OLD_PROTECT_OFF]
    call    qword ptr [r12+SCRATCH_OFF+110h] ; VirtualProtect
    cld
    mov     rdi, rbp
    lea     rsi, [r12+ORIG_BYTES_OFF]
    mov     ecx, 5
    rep movsb
    mov     rcx, rbp
    mov     edx, 5
    mov     r8d, dword ptr [r12+OLD_PROTECT_OFF]
    lea     r9, [r12+OLD_PROTECT_OFF]
    call    qword ptr [r12+SCRATCH_OFF+110h] ; VirtualProtect (restore)
    mov     rcx, -1
    mov     rdx, rbp
    mov     r8d, 5
    call    qword ptr [r12+NTFLUSH_SLOT_OFF] ; NtFlushInstructionCache
    jmp     restore_registers

set_result_no_restore:
    ; The entry bytes cannot be restored (VirtualProtect or the flush could
    ; not be resolved). Record the failure and park: jumping into the patched
    ; entry would just re-enter this stub, and running past it is impossible
    ; without the restore.
    mov     [r12+RESULT_OFF], eax
park_loop:
    pause
    jmp     park_loop

restore_registers:

    ; ---- restore registers and jump to the original entry ----
    ldmxcsr dword ptr [r12+SCRATCH_OFF+100h]
    movdqu  xmm0, [r12+SCRATCH_OFF+00h]
    movdqu  xmm1, [r12+SCRATCH_OFF+10h]
    movdqu  xmm2, [r12+SCRATCH_OFF+20h]
    movdqu  xmm3, [r12+SCRATCH_OFF+30h]
    movdqu  xmm4, [r12+SCRATCH_OFF+40h]
    movdqu  xmm5, [r12+SCRATCH_OFF+50h]
    movdqu  xmm6, [r12+SCRATCH_OFF+60h]
    movdqu  xmm7, [r12+SCRATCH_OFF+70h]
    movdqu  xmm8, [r12+SCRATCH_OFF+80h]
    movdqu  xmm9, [r12+SCRATCH_OFF+90h]
    movdqu  xmm10, [r12+SCRATCH_OFF+0A0h]
    movdqu  xmm11, [r12+SCRATCH_OFF+0B0h]
    movdqu  xmm12, [r12+SCRATCH_OFF+0C0h]
    movdqu  xmm13, [r12+SCRATCH_OFF+0D0h]
    movdqu  xmm14, [r12+SCRATCH_OFF+0E0h]
    movdqu  xmm15, [r12+SCRATCH_OFF+0F0h]
    mov     rax, rbx
    add     rax, 22222222h                   ; FIXUP: original entrypoint RVA
    xchg    rax, [r14+112]                   ; saved-rax slot becomes the target
    mov     rsp, r14
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     r11
    pop     r10
    pop     r9
    pop     r8
    pop     rbp
    pop     rdi
    pop     rsi
    pop     rdx
    pop     rcx
    pop     rbx
    pop     rax
    popfq
    jmp     rax

; ---------------------------------------------------------------------------
; resolve_export: walk a module's export table by name hash.
;   in:  rbx = module base, edi = ror13 hash of the ASCII export name
;   out: rax = function VA, or 0 when not found or forwarded
;   clobbers: rax, rcx, rdx, rsi, r8, r9, r10, r11
; ---------------------------------------------------------------------------
resolve_export:
    mov     eax, [rbx+3Ch]                   ; e_lfanew
    lea     r8, [rbx+rax]                    ; PE signature
    mov     eax, [r8+88h]                    ; export directory RVA (PE32+)
    test    eax, eax
    jz      export_not_found
    lea     r9, [rbx+rax]                    ; export directory
    mov     r10d, [r9+18h]                   ; NumberOfNames
    mov     r11d, [r9+20h]                   ; AddressOfNames RVA
    lea     r11, [rbx+r11]
    xor     ecx, ecx
export_name_loop:
    cmp     ecx, r10d
    jae     export_not_found
    mov     esi, [r11+rcx*4]
    lea     rsi, [rbx+rsi]                   ; candidate name
    xor     edx, edx
export_hash_loop:
    movzx   eax, byte ptr [rsi]
    test    al, al
    jz      export_hash_done
    ror     edx, 13
    add     edx, eax
    inc     rsi
    jmp     export_hash_loop
export_hash_done:
    cmp     edx, edi
    je      export_name_found
    inc     ecx
    jmp     export_name_loop
export_name_found:
    mov     eax, [r9+24h]                    ; AddressOfNameOrdinals RVA
    lea     rax, [rbx+rax]
    movzx   ecx, word ptr [rax+rcx*2]
    mov     eax, [r9+1Ch]                    ; AddressOfFunctions RVA
    lea     rax, [rbx+rax]
    mov     eax, [rax+rcx*4]                 ; function RVA
    mov     edx, eax
    sub     edx, [r8+88h]                    ; RVA - export directory RVA
    cmp     edx, [r8+8Ch]                    ; inside the directory = forwarder
    jb      export_not_found
    lea     rax, [rbx+rax]
    ret
export_not_found:
    xor     eax, eax
    ret
static_stub endp
end
```
