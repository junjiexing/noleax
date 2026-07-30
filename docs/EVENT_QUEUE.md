# Preallocated MPSC Event Queue

> 状态：P5.4 Windows x64 NT Heap 五 API 与 NT VM 两 API 的共享队列域完成
> 范围：固定宽度原始事件、跨 API 顺序、overflow 归因及后台 writer 消费边界

## 1. 合同

hook 热路径使用固定容量、multiple-producer/single-consumer 队列。队列必须在安装 hook 前完成全部
内存分配，生产者路径不得调用 allocator、获取 mutex、等待 condition variable、执行 I/O 或抛出
异常。

容量必须是不小于 2 的 2 次幂。构造失败或容量非法发生在冷路径，hook 不会半安装。生产者路径是
lock-free 而非 wait-free：生产者竞争 reservation 时可以重试 CAS，但队列满时立即失败，不等待
consumer 腾出空间。

## 2. Ring 算法

每个 slot 包含一个 64-bit generation sequence 和一个定长、trivially-copyable event。三个控制位置
分别放在独立 cache line：

- 原子 producer reservation cursor；
- 仅由 consumer 修改的 dequeue cursor；
- 原子 dropped counter。

生产者流程：

1. 根据 cursor 和 mask 定位 slot；
2. acquire-load slot sequence，判断可写、已满或需要刷新 cursor；
3. CAS reservation cursor，获得该 slot 的唯一所有权；
4. 原地填充 event，并获得连续的 1-based `queue_sequence`；
5. release-store slot sequence，向 consumer 发布完整 event。

consumer 只按 reservation 顺序读取。它 acquire-load slot sequence，复制完整 event 后用 release-store
把 slot 推进到下一 generation。较晚的 producer 即使先写完，也不能越过尚未 publish 的早期 slot，
因此队列输出顺序与 reservation 顺序一致。

`reset_quiescent` 只允许在没有 producer/consumer 时调用。独立 hook 拥有的 queue 在安装前重置；
P5.3 heap 组合对象和 P5.4 `NtMemoryHooks` 各自拥有一个共享 queue 域；同一域内 API 共用 sequence，
两个域之间不依赖时间戳合并。当前 adapter 每进程只允许一次成功安装。卸载后才允许最终 drain。
replacement lifecycle 保证 reset、final drain 和对象销毁前没有 producer；
详见 [HOOK_QUIESCENCE.md](HOOK_QUIESCENCE.md)。

## 3. Overflow 与 Loss

队列满时，当前 event 不获得 reservation 和 `queue_sequence`，生产者立即返回 false，并以饱和 CAS
增加 64-bit dropped counter。计数到 `UINT64_MAX` 后保持饱和，不允许回绕为零。

底层 queue 保留总 dropped counter；五个 NT Heap hook 与两个 NT VM hook 都分别维护饱和 dropped
counter，使单 consumer 能把 overflow 归因到 api_id。writer 把所选 API 的非零 interval count汇总为：

~~~text
LossReason   = queue_full
LossLocation = agent_queue
estimated_event_count = dropped interval count
sequence_range = absent
tick_range = absent
~~~

被拒绝的 event 没有 reservation，因此不能编造精确 sequence/tick range。任何 queue Loss 都设置
`event_loss`，使 outstanding 分析保持 incomplete。

## 4. Windows 原始事件

P5.4 的统一 in-process event 固定为 640 bytes，包含：

- queue sequence；
- QueryPerformanceCounter ticks；
- thread id；
- create/allocate/reallocate/free/destroy/VM allocate/VM free operation；
- heap handle、flags、requested size/address、create lock/parameters；
- NT VM target PID、调用前后 base/size、zero bits、protection/free type 和规范化 mapping base/size；
- result address、raw BOOLEAN result 和 success/failure/exception；
- exception NTSTATUS；
- 最多 64 帧、520-byte 的定长 `CapturedStack`。

只有 guard 分类为 outermost 的调用会在 original 返回后尝试入队；recursive 和 internal-thread 调用
仍只调用 trampoline。生产者先取得 slot，再直接向 slot 捕获栈；queue 已满时不会执行无用 unwind。
replacement 在 original 返回后立即保存 `LastError`，完成计时、捕获和入队后恢复，因此新增的
Windows API 与队列操作不会改变目标可观察到的错误状态。栈状态和失败合同见
[STACK_CAPTURE.md](STACK_CAPTURE.md)。

默认 adapter 容量为 16,384 个 event。包含 per-slot sequence 后预分配约 10.1 MiB；测试
harness 显式使用 256 个 slot 以稳定制造 overflow。writer 只消费该固定队列，不在 hook 热路径
扩容；未来产品配置仍需由 agent 根据 byte budget 推导容量。

## 5. 验证

单元测试覆盖：

- 非法容量、FIFO、slot 多轮复用和 quiescent reset；
- 8 producer 无 loss 并发，验证 16,000 个 event 无重复、无损坏、sequence 连续；
- 8 producer 固定满队列，验证每次失败均进入 dropped count；
- 8 producer 与单 consumer 同时运行，验证 publish/acquire 和 reuse。

真实组合 hook harness 与 NT VM race 在卸载后 drain 各自队列，逐项检查 sequence、ticks、thread、
operation、status/result 和 stack 编码一致性，并要求：

~~~text
sum(five_api_recordable) == dequeued + sum(five_api_dropped)
sum(five_api_dropped) > 0
sum(two_vm_api_recordable) == dequeued + sum(two_vm_api_dropped)
~~~

同一 MD/MT workload 的 hooked/unhooked 摘要仍须逐字节一致。

~~~powershell
. .\scripts\Enter-NoleaxDevShell.ps1
cmake --build --preset windows-x64-debug
cmake --build --preset windows-x64-release
ctest --preset windows-x64-debug -R "bounded MPSC|rtl-.*heap|rtl-allocate-heap-passthrough" --output-on-failure
ctest --preset windows-x64-release -R "bounded MPSC|rtl-.*heap|rtl-allocate-heap-passthrough" --output-on-failure
~~~
