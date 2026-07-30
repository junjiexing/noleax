# Windows NT section view hook

> 状态：P5.5 Windows x64 完成；产品 profile 等待 P5.7 启用

## 1. 规范化入口

`NtMemoryHooks` 在 P5.5 协调安装：

- `NtMapViewOfSection`；
- `NtUnmapViewOfSection`；
- `NtUnmapViewOfSectionEx`，作为新版 Windows `UnmapViewOfFile` 的兼容入口。

两个 unmap 入口共享逻辑 `api_id=9`、计数器、queue 和 generation 语义；Ex 的 `Flags` 写入事件
公共 flags。`NtMapViewOfSection` 使用 `api_id=8`。SDK 未公开 `SECTION_INHERIT` 类型，adapter 使用
ABI 等宽的 `ULONG`，合同测试固定验证 `ViewUnmap=2`。

基础 unmap 与 Ex 仍有各自精确 original trampoline、Hoox lease 和安装状态；两者共用 replacement
in-flight 生命周期，只有两个 target 都 revert 且 callback quiescent 后才释放 trampoline。

## 2. 热路径与 raw event

P5.5 将统一 `RtlHeapEvent` 扩展为固定 664 bytes，新增：

- raw section handle；
- 调用前 section offset；
- commit size；
- inherit disposition；
- map 的 requested/result base、requested/result view size、zero bits、allocation type 和 protection；
- unmap/Ex 的 address、flags、NTSTATUS 与目标进程分类。

replacement 继续只做安全参数读取、original 调用、LastError 保存/恢复、有界栈捕获、原子计数和
预分配 queue 写入。异常路径由 SEH filter 记录，且不吞掉异常。五个单独 NT Heap adapter 的
install/uninstall 入口也标记为 internal scope，防止 Hoox 安装其他 hook 时的临时 section mapping
污染用户事件或灌满 queue。

## 3. Generation 语义

当前进程成功 map 创建单调 `MappingId`；同一 section 的每个 view 都是独立 generation。成功 unmap
按包含目标地址的 live view 匹配，因此 Windows 允许的“view 内任意地址”输入会规范化为 generation
基址后写入 trace。失败不结束 generation。

成功但未知的本进程 unmap 按 CaptureScope 写为 `preexisting` 或 `unmatched`，不伪造 MappingId。
远程进程 map/unmap 保存 process handle、解析到的 PID 和 raw 结果，但不加入本进程 outstanding 状态。

## 4. Windows 包装路径

当前 Windows 11 的 `MapViewOfFile` 经过 `NtMapViewOfSection`，`UnmapViewOfFile` 经过
`NtUnmapViewOfSectionEx`。同时 hook legacy 与 Ex unmap 是避免 wrapper view 假阳性的必要条件；二者
仍归一为同一种 trace operation，避免重复生命周期。

## 5. 自动门禁

合同与 trace 测试覆盖：

- pagefile-backed 和 file-backed section；
- 非零 allocation-granularity offset、非页整倍数请求 size；
- 同一 section 多 view、read-only/read-write；
- view 内部地址 unmap、重复 unmap、无效 section NTSTATUS 和 LastError 差分；
- `MapViewOfFile`/`UnmapViewOfFile`；
- preexisting 与 unmatched CaptureScope；
- suspended child 的 remote map/unmap；
- MappingId 唯一性、EventStream、GenerationTracker、statistics 和零 event loss；
- legacy/Ex unmap、allocate/free、map 的组合 quiescence race。

Hardened registry、CFG/CET image 检查及 Application Verifier/Full Page Heap 均包含 section contract、
组合 trace 和 race 目标。

最终结果：Debug/Release 195/195、hardened 216/216、21 个 PE、五组 race 100/100、长 ABI 差分
3/3、Application Verifier/Full Page Heap 3/3；本轮 16 个 IFEO target key 全部清理。
