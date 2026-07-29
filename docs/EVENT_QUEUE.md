# Preallocated MPSC Event Queue

> 状态：P4.5 Windows x64 完成
> 范围：`RtlAllocateHeap` 原始事件入队与 overflow 统计；尚不写 trace

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

`reset_quiescent` 只允许在没有 producer/consumer 时调用。adapter 每次安装前重置队列；卸载后才允许
最终 drain。队列对象销毁和 replacement in-flight 的完整协调仍属于 P4.8。

## 3. Overflow 与 Loss

队列满时，当前 event 不获得 reservation 和 `queue_sequence`，生产者立即返回 false，并以饱和 CAS
增加 64-bit dropped counter。计数到 `UINT64_MAX` 后保持饱和，不允许回绕为零。

单 consumer 可以通过原子 exchange 获取一个精确的 dropped interval count。P4.7 writer 必须把非零
值转换为：

~~~text
LossReason   = queue_full
LossLocation = agent_queue
estimated_event_count = dropped interval count
sequence_range = absent
tick_range = absent
~~~

被拒绝的 event 没有 reservation，因此不能编造精确 sequence/tick range。任何 queue Loss 都设置
`event_loss`，使 outstanding 分析保持 incomplete。

## 4. RtlAllocateHeap 原始事件

P4.5 的 in-process event 固定为 56 bytes，包含：

- queue sequence；
- QueryPerformanceCounter ticks；
- thread id；
- heap handle、flags、requested size；
- result address 和 success/failure。

只有 guard 分类为 outermost 的调用会在 original 返回后尝试入队；recursive 和 internal-thread 调用
仍只调用 trampoline。replacement 在 original 返回后立即保存 `LastError`，完成计时和入队后恢复，
因此新增的 Windows API 与队列操作不会改变目标可观察到的错误状态。

默认 adapter 容量为 65,536 个 event。测试 harness 显式使用 256 个 slot 以稳定制造 overflow；容量
最终由 agent 配置和 byte budget 推导属于 P4.7。

## 5. 验证

单元测试覆盖：

- 非法容量、FIFO、slot 多轮复用和 quiescent reset；
- 8 producer 无 loss 并发，验证 16,000 个 event 无重复、无损坏、sequence 连续；
- 8 producer 固定满队列，验证每次失败均进入 dropped count；
- 8 producer 与单 consumer 同时运行，验证 publish/acquire 和 reuse。

真实 hook harness 在卸载后 drain 队列，逐项检查 sequence、ticks、thread 和 status/result 一致性，
并要求：

~~~text
recordable_call_count == dequeued_event_count + dropped_event_count
dropped_event_count > 0
~~~

同一 MD/MT workload 的 hooked/unhooked 摘要仍须逐字节一致。

~~~powershell
. .\scripts\Enter-NoleaxDevShell.ps1
cmake --build --preset windows-x64-debug
cmake --build --preset windows-x64-release
ctest --preset windows-x64-debug -R "bounded MPSC|rtl-allocate-heap-passthrough" --output-on-failure
ctest --preset windows-x64-release -R "bounded MPSC|rtl-allocate-heap-passthrough" --output-on-failure
~~~
