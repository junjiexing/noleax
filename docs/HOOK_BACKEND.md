# Noleax HookBackend

> 后端：Hoox v0.2.0 `replace_fast`（以 amalgamation 形式 vendor 在 `third_party/hoox`）

## 1. 边界

`HookBackend` 是 Noleax 业务代码与 Hoox 之间的唯一适配层。公开头文件不包含 `hoox.h`，也不暴露
Hoox enum、interceptor 或 option 类型。agent 通过 `noleax::hook-backend` 静态库使用后端。

通用 backend 生命周期测试使用无副作用 fixture；真实
`RtlAllocateHeap` passthrough ABI 差分已在该边界之上完成，见
[RTL_ALLOCATE_HEAP_HOOK.md](RTL_ALLOCATE_HEAP_HOOK.md)。

## 2. 安装策略

`install_fast(target, replacement)` 固定使用：

- `hoox_interceptor_replace_fast`；
- online scenario；
- checked relocation policy；
- 非空 original trampoline 输出。

真实 allocator adapter 还会传入 `OriginalTrampolineSlot`。backend 用外层 Hoox transaction 延迟
激活，先完成 entry bookkeeping，再以 release-store 发布 original，最后提交代码 patch；replacement
以 acquire-load 读取。该顺序消除 hook 已生效但 original 尚未可用的递归窗口。普通 fixture 可以
省略 slot。

target/replacement 为空或相同会在进入 Hoox 前返回 `invalid_argument`。同一 backend 的重复 target
返回 `already_installed` 和已有 original；其他 backend 已替换该 target 时映射为
`already_replaced`。Hoox 的 wrong signature、policy violation 和 wrong type 均保留为不同状态，不能
折叠成模糊的安装失败。

如果 Hoox 报告成功却没有提供 original，backend 会立即 revert 并 flush，返回
`missing_original`。记录已安装 hook 时若 C++ 容器分配抛出异常，同样先执行 revert/flush 再重新
抛出，避免留下无法管理的活动 hook。

## 3. 状态与 teardown

一个 backend 的正常状态顺序为：

1. 构造时 `hoox_init` 并取得带引用的 interceptor singleton。
2. `install_fast` 记录 target、replacement 和 original。
3. 普通 target 的 `uninstall` 先 revert，再尝试 flush；allocator adapter 固定用
   `uninstall(target, 0)` 将 revert 与 flush 分开。
4. flush 完成后允许再次安装；未完成时进入 `teardown_pending`，拒绝新安装。
5. `shutdown` 在一个 Hoox transaction 中 revert 全部 target，flush 成功后 unref interceptor 并
   `hoox_deinit`，随后永久进入 stopped 状态。

`uninstall(target, 0)` 可用于只执行 revert、不进行 flush，并明确返回 `teardown_pending`。调用方
之后必须调用 `flush`。所有控制面方法由 backend mutex 串行化；该 mutex 不在 replacement 热路径
中使用。

析构函数等价于 best-effort shutdown。如果 bounded flush 仍失败，backend 会故意保留 Hoox 的
interceptor/lifecycle 引用，宁可由进程退出回收，也不释放仍可能执行的 trampoline 内存。这是
fail-safe 泄漏，不代表 DLL 已满足安全卸载条件。

## 4. 必须区分的 in-flight 范围

Hoox `flush` 只知道其 trampoline 是否仍被使用。`replace_fast` 是直接跳到 replacement，以下窗口
不在 Hoox usage counter 中：

- replacement 已进入但尚未调用 original；
- original 已返回但 replacement 尚未退出；
- replacement 选择不调用 original。

backend 另提供 trampoline lifetime lease：lease 存在时允许 revert，但拒绝 flush/deinit。
allocator adapter 在 Noleax replacement in-flight 归零后才释放 lease。完整的三路 gate、Windows
RWX patch 暂停、模块引用和 patch rendezvous 见 [HOOK_QUIESCENCE.md](HOOK_QUIESCENCE.md)。该协议不能通过单纯增大
Hoox flush 次数替代。

## 5. 多实例与线程安全

Hoox interceptor 是进程 singleton，Hoox lifecycle 自带引用计数。多个 `HookBackend` 可以同时
存在：各自跟踪自己的 target；对同一 target 的冲突由 Hoox 返回 `already_replaced`。一个实例
shutdown 不会销毁仍被其他实例引用的 singleton。

同一对象的方法可以由多个控制线程调用，但对象析构仍要求外部先停止对该 C++ 对象的调用。业务
replacement 不应调用 `HookBackend` 控制面方法。

Hoox transaction 属于进程 singleton，而不是某个 `HookBackend` 实例。adapter 因此还用模块级
control mutex 覆盖完整的 begin/end 区间，防止两个 backend 实例的 transaction 跨线程嵌套，保证
`install_fast` 返回时本次 patch 已经激活。该锁只用于安装和批量 shutdown，不进入 replacement。

## 6. Hoox 生命周期修复

Hoox 早期的 `HxPrivate` 在 Windows 上通过 `FlsAlloc` 注册 DLL 内部回调，但
`_hoox_interceptor_deinit` 未释放该 FLS index。agent 静态链接 Hoox 后，如果 DLL 被
`FreeLibrary` 卸载，进程退出时 `ntdll!RtlpFlsDataCleanup` 仍可能跳到已经卸载的回调地址。

该修复已上游化（v0.2.0，`hx_private_clear`）并随 vendored amalgamation 带入：

- deinit 清理当前 interceptor context 后注销 FLS index；
- `FlsFree` 触发仍有值的 fiber callback，并从进程注销 callback；
- 将 key 复位，后续 `hoox_init` 可以重新分配；
- 提供 `pthread_key_delete` 对称实现，保持 POSIX 源码可编译，但当前只验证 Windows x64。

修复不改变 `replace_fast`、relocator 或 trampoline 行为。

## 7. 测试

专用 fixture 是独立 DLL，提供两个 `noinline`、足够长且 Release 下保持优化的导出函数，避免上游
同一编译单元短函数测试的已知失真。测试覆盖：

- replacement 调用计数、original 返回值和替换后返回值；
- null/相同地址、同实例重复安装和跨实例冲突；
- 两个 backend 实例并发安装时 transaction 不交错；
- 单 target uninstall、显式 deferred teardown 和后续 flush；
- 两个 target 的 transaction shutdown；
- 析构自动回滚和 25 次完整 init/install/call/revert/deinit 循环；
- shutdown 幂等及 stopped 状态；
- agent DLL 通过 adapter 完成 Hoox linkage smoke test，并在 `FreeLibrary` 后正常退出；
- original slot 在 transaction 激活前发布；
- agent unload smoke 在 Debug/Release 下各连续运行 20 次；
- Debug/Release。

运行方法：

~~~powershell
. .\scripts\Enter-NoleaxDevShell.ps1
cmake --build --preset windows-x64-debug
ctest --preset windows-x64-debug -R "hook backend" --output-on-failure
ctest --preset windows-x64-debug -R "agent.load-and-link-hoox" --output-on-failure
ctest --preset windows-x64-debug -R "agent.load-and-link-hoox" --repeat until-fail:20
~~~

backend 生命周期测试不构成真实 allocator hook 通过结论；真实 allocator hook 的验证见
[RTL_ALLOCATE_HEAP_HOOK.md](RTL_ALLOCATE_HEAP_HOOK.md)。
