# Linux Hook API Matrix

> backend：Hoox v0.2.0 replace_fast（含 near-redirect 回退）
> target：Linux x86-64 / glibc
> 状态：M3 初版（linux-glibc-heap 组）

## 1. Profile

| Profile | API |
|---|---|
| linux-glibc-heap | malloc、calloc、realloc、free、posix_memalign、aligned_alloc、memalign、reallocarray |

## 2. 通用合同

每个 adapter 必须：

- 使用与 System V AMD64 ABI 完全匹配的函数类型。
- 使用 Hoox replace_fast 获得 original trampoline（短序言目标自动使用 near-redirect
  回退，见 [HOOK_BACKEND.md](HOOK_BACKEND.md) 的 Linux 注记）。
- 调用 original 恰好一次。
- 在 original 返回后立刻保存 errno，事件记录完成后恢复；返回值原样透传。
- 不在 replacement 中分配 heap、解析符号、写文件或等待阻塞锁。
- 只写入预分配事件队列。
- 递归入口（guard 分类 recursive/internal-thread）只计数、不记录事件。
- 提供独立 in-flight counter 与统计计数；支持两阶段停止。

## 3. 逐 API 语义

### 3.1 malloc（api_id 10）

- `malloc(n)`：成功记录 `requested_size=n`、`result_address=ptr`；失败（NULL）记录
  `operation_result=errno`（ENOMEM）。
- `malloc(0)`：glibc 返回非 NULL 最小块，按成功记录（大小 0）。

### 3.2 calloc（api_id 11）

- `calloc(nmemb, size)`：`requested_size=nmemb*size`、`count=nmemb`。glibc 在分配前做
  乘法溢出检查（`__builtin_mul_overflow`），溢出返回 NULL 并置 ENOMEM——事件即失败事件，
  语义与实际分配行为一致。
- calloc 内部经 hidden alias 进入 malloc 共享代码：该入口被 hook 覆盖，但 guard 递归抑制
  保证不产生第二条事件。

### 3.3 realloc（api_id 12）

- `realloc(p, n)`：`address=p`、`requested_size=n`；成功 `result_address=新指针`。
- `realloc(NULL, n)`：等价 malloc，`address=0`、无旧代际，effect=kNewGeneration。
- `realloc(p, 0)`：glibc 释放 p 并返回 NULL——按成功记录、effect=kFreed（不视为失败）。
- 迁移与原地扩缩都由 writer 的旧 id 查找 + 新代际配对表达。

### 3.4 free（api_id 13）

- `free(p)`：`address=p`，成功事件。free 不改变 errno（glibc 行为），replacement 仍按
  合同保存/恢复。
- `free(NULL)`：glibc 直接返回，按成功记录、`address=0`。
- 未知指针（捕获开始前已存在的分配）按 scope 记 `unmatched`/`preexisting`，见
  [TRACE_FORMAT.md](TRACE_FORMAT.md) 的 status 语义。

### 3.5 posix_memalign（api_id 14）

- `posix_memalign(&memptr, alignment, size)`：返回码即错误码（**不设 errno**），
  `operation_result` 记录该返回码；成功时 `result_address=*memptr`、
  `alignment=alignment`、`requested_size=size`。
- 非法 alignment（非 2 的幂或小于 sizeof(void*)）返回 EINVAL——失败事件。

### 3.6 aligned_alloc / memalign（api_id 15/16）

- `aligned_alloc(alignment, size)` / `memalign(alignment, size)`：
  `alignment=alignment`、`requested_size=size`、成功 `result_address=ptr`。
- 这两个公开符号是跳转到共享实现的短 stub；hook 打在公开入口（near-redirect），
  每个公开调用恰好一条事件，语义按入口参数保留。

### 3.7 reallocarray（api_id 17）

- `reallocarray(p, nmemb, size)`：operation=kReallocate，`count=nmemb`、
  `requested_size=nmemb*size`。glibc 先做乘法溢出检查（EOVERFLOW），再经
  `realloc@plt` 分配——内层 realloc 入口由递归抑制保证不产生第二条事件。

## 4. 事件与统计不变式

- `queue_sequence` 从 1 连续；事件携带 api_id、线程 id、单调时钟 ticks、调用栈 id。
- 逐 api_id：`observed == successful + failed`、`observed == written + filtered + dropped`。
- `capture.min_size` 只过滤创建侧（kAllocate 类），realloc/free 始终记录；被过滤调用
  计入统计但无事件、无 sequence、无调用栈。

## 5. Virtual Memory 组（linux-virtual-memory / linux-native）

### 5.1 mmap（api_id 18）

- 成功：`result_address`=映射基址、`requested_size`=length、`protection`=PROT_* 位、
  `map_flags`=flags；匿名映射 `section_handle` 记 UINT64_MAX，文件映射记录 fd 与
  `section_offset`。
- `MAP_FAILED` 为失败事件，`operation_result`=errno。
- 创建侧应用 `capture.min_size` 过滤。
- 代际：匿名映射产生 VmAllocate 记录（新 mapping_id）；文件映射产生 Map 记录。
- `mmap64` 与 `mmap` 同地址（x86-64 glibc），不单独安装，调用 mmap64 的调用经同地址
  入口被同一 hook 捕获。

### 5.2 munmap（api_id 19）

- `address`=区间起点、`requested_size`=length；成功按代际配对关闭映射（匿名 → VmFree
  带 release 位，文件映射 → Unmap），未知区间记 unmatched。
- 不过滤、始终记录。

### 5.3 mremap（api_id 20）

- `address`=旧区间起点、`requested_size`=旧尺寸、`count`=新尺寸、`map_flags`=flags、
  `result_address`=新基址。`MREMAP_MAYMOVE` 的第 5 个变参在 flags 命中时读取并记录。
- 原地增长保留 mapping_id（analyzer 允许同基址扩尺寸）；迁移展开为
  VmFree（旧 mapping_id）+ VmAllocate（新 mapping_id）记录对。
- `MAP_FAILED` 为失败事件，不改代际。

### 5.4 组内合同

与 heap 组相同：errno 保存/恢复、恰好一次 original、递归抑制、两阶段停止。
glibc 分配器自身的 arena 增长（main arena 的 brk、新 arena 的内部 mmap）不经公开
符号或经递归抑制，不产生事件——进程 RSS 与事件字节数不会逐字节相等，属预期。

## 5. 验证

逐 API 的合同测试在 `tests/integration/linux_glibc_heap_hooks_probe.cpp`（字段、errno、
边界形态、递归抑制）；Hoox 层的 target matrix 用例锁定全部物理 export 的可安装性
（`tests/unit/hook_backend_posix_test.cpp`）。
