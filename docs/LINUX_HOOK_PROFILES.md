# Linux Hook Profiles

> 范围：registry、profile 选择、热路径过滤、统计与停止顺序（Linux 侧）
> 状态：已实现（Linux 移植 M3）

## 1. 单一 registry

产品代码只维护一份 Linux hook registry（`include/noleax/agent/linux/hook_registry.hpp`）。
每项给出稳定 `api_id`、规范名称、模块与物理 export；profile 协调器、writer 和测试均以此表
为边界。Windows 内建占用 api_id 1–9，Linux 内建从 10 起；自定义 hook 沿用共享的
`kCustomHookApiIdBase = 0x1000`。

| api_id | 规范 API | 物理 export | 组 | `capture.min_size` |
|---:|---|---|---|---|
| 10 | malloc | malloc | glibc Heap | 是 |
| 11 | calloc | calloc | glibc Heap | 是 |
| 12 | realloc | realloc | glibc Heap | 否 |
| 13 | free | free | glibc Heap | 否 |
| 14 | posix_memalign | posix_memalign | glibc Heap | 是 |
| 15 | aligned_alloc | aligned_alloc | glibc Heap | 是 |
| 16 | memalign | memalign | glibc Heap | 是 |
| 17 | reallocarray | reallocarray | glibc Heap | 否 |

自动测试双向检查 registry 与实现一一对应，并确认所有物理 export 都能从 `libc.so.6`
解析（`tests/unit/hook_backend_posix_test.cpp` 的 target matrix 用例）。

## 2. Profile

| profile | 逻辑 API |
|---|---|
| `linux-glibc-heap` | 10–17（malloc 族全部） |

`linux-virtual-memory` 与 `linux-native`（mmap 族及其并集）在 M4 落地，届时 registry 扩展
api_id 18–20（mmap/munmap/mremap）。

## 3. 覆盖语义（与 Windows 的关键差异）

Windows 版选择 ntdll Rtl/Nt 作为一切分配路径的隘口；Linux 没有等价单一隘口，本 profile 以
glibc 公开符号为隘口。实测确认（glibc 2.43，`nm -D` 地址比对 + hook 实证）：

- `__libc_malloc` 等隐藏别名与公开符号**同地址**，inline hook 打在共享代码入口上——libc
  内部走 `__libc_*` 的分配（fopen 缓冲区、strdup 等）**同样被记录**。这比 LD_PRELOAD 符号
  覆盖方案的覆盖面大（后者拦不到 hidden alias 调用）。
- 公开符号之间的内部互调（`reallocarray` → `realloc@plt`、`memalign`/`aligned_alloc` →
  共享实现）在双 hook 下由 **guard 递归抑制**保证单事件：内层入口分类为 recursive，只计数
  不记录。reallocarray 调用只产生 reallocarray 事件。
- 明确不覆盖（与 Windows "只覆盖 Rtl/Nt" 同类边界）：ld.so 私有最小分配器（bootstrap 早期
  窗口）、目标直接 `syscall(SYS_*)`、非 glibc 体系分配器（jemalloc/mimalloc，M7 自定义
  hook 场景）、静态链接目标（LD_PRELOAD 不适用）、glibc 分配器自身的 arena 增长
  （brk/mmap 内部路径——不是应用分配，属预期排除）。

## 4. 通用合同

每个 adapter 必须（与 [HOOK_API_MATRIX.md](HOOK_API_MATRIX.md) §2 同构）：

- 使用与 System V AMD64 ABI 匹配的函数类型。
- 使用 Hoox replace_fast 获得 original trampoline（短序言目标自动走 near-redirect 回退）。
- 调用 original 恰好一次。
- 在 original 返回后保存 errno，记录完成后恢复（posix_memalign 不设 errno，返回码原样
  透传）。
- 不在 replacement 中分配 heap、解析符号、写文件或等待阻塞锁。
- 只写入预分配事件队列。
- 提供独立 in-flight counter 与统计计数。
- 支持两阶段停止（逻辑停录 → 物理卸载），替换函数全部位于 `.nlxhk` 段（patch
  rendezvous 覆盖）。

逐 API 语义（calloc 溢出检查时机、realloc(p,0)、free(NULL)、posix_memalign 返回码等）
见 [LINUX_HOOK_API_MATRIX.md](LINUX_HOOK_API_MATRIX.md)。

## 5. 统计守恒

与 Windows 相同的不变式，逐 api_id 成立：

- `observed == successful + failed`
- `observed == written + filtered + dropped`（written 为成功事件入队数）

writer finalize 时对账，不符即失败（trace 不带出）。

## 6. 验证

- hook 合同探针：`tests/integration/linux_glibc_heap_hooks_probe.cpp`（字段、计数对账、
  递归抑制、多线程）。
- 端到端：`noleax run --hook-profile linux-glibc-heap` 对工作负载目标的捕获产物经
  `analyze` 三模式校验（见 tests 的 Linux e2e）。
