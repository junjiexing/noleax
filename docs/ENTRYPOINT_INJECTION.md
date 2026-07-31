# Entrypoint Code 注入（P7B）

> 状态：P7B Windows x64 完成
> 注入方式：`entrypoint-code`，仅 `run`（suspended launch）

## 1. 目的与适用范围

`entrypoint-code` 在 suspended launch 的目标主镜像入口点上临时写入一段跳转，让进程一恢复
运行就先执行注入 stub：加载 agent、完成 bootstrap、等待 capture ready，然后把入口点原始字节
写回、刷新指令缓存并跳回原入口。与 `remote-thread` 相比它不创建任何线程；与
`thread-hijack` 相比它不存在线程选择问题，且入口点是进程级确定安全点。

`attach` 不支持本方式（没有“尚未执行的入口点”可用），配置校验在选择前直接报错。

## 2. 流程

1. 控制器以 `CREATE_SUSPENDED` 创建目标。
2. 在目标内存中定位主镜像（`VirtualQueryEx` + 映射文件名匹配），读取 PE 头得到
   `AddressOfEntryPoint`。
3. 备份入口点前 0x20 字节；若入口以 `endbr64` 开头，则补丁起点后移 4 字节，保持
   `endbr64` 完整（loader 对入口点是间接调用，CET/IBT 目标必须落在 `endbr64` 上）。
4. 在补丁位置写入 12 字节 `mov rax, stub; jmp rax`（先 `VirtualProtectEx` 改为 RWX，写后
   `FlushInstructionCache`；多字节补丁整体覆盖，执行只从补丁首字节进入，不存在指令边界
   部分执行问题）。
5. stub 与数据写入独立分配的 RX/RW 远程内存；stub 首指令为 `mov r12, imm64`，控制器在写入
   前把 imm64 修补为数据块地址（入口点调用约定不提供寄存器参数）。
6. 恢复主线程。stub 保存全部寄存器（GP、XMM0-15、MXCSR、EFlags），执行
   `LdrLoadDll(agent)` → `noleax_agent_bootstrap` → 轮询
   `noleax_agent_capture_is_ready`（有界）。
7. 无论成功或失败，stub 都把入口点原始字节写回、`NtFlushInstructionCache`、置 restored
   标志、恢复寄存器（rax 借用为最终跳转寄存器，其余逐项恢复）并 `jmp` 到原入口——函数
   起点跳转在 CET/IBT 下合法，shadow stack 也不受影响（stub 内部调用保持平衡）。
8. 控制器的 IPC 握手成功后调用 `finish()`：等待 restored 标志，回读入口点字节并与备份
   逐字节比较，再把页面保护改回原始值。任何失败都不会以损坏的入口点恢复目标。

stage 编码：1=`LdrLoadDll` 已返回（附 NTSTATUS），2=bootstrap 已返回（附结果码），
3=capture ready，4=ready 等待超时。握手失败时 `describe_failure()` 读取 stage 生成诊断。

## 3. 关键实现细节

- stub 用 `mov r14, rsp` 记录寄存器压栈后的栈顶，恢复前先 `mov rsp, r14` 再逐项 `pop`；
  早期版本缺少这一步，`pop` 序列读到的是 `and rsp,-16; sub rsp,60h` 之后的调用者栈垃圾，
  导致目标在 stub 发出完成信号后立刻崩溃（现为回归门禁，由 launch 集成测试覆盖）。
- kernel32 在 freshly suspended 进程里尚未映射，stub 侧刷缓存用
  `ntdll!NtFlushInstructionCache`（永远存在），不解析 kernel32 导出。
- stub 的 ready 轮询有界（约 2^27 次）；超时后 stage=4，stub 仍然恢复入口字节并跳回原入口，
  目标以未插装状态继续运行，控制器随后报错并终止 launch。
- 失败路径（agent 缺少导出、路径非法、镜像未找到、ready 超时、字节校验失败）全部在
  launch 既有回滚语义内处理：终止 suspended 目标，不产生半修补进程。

## 4. 测试

- `entrypoint patch offset` 单元测试：`endbr64` 检测返回补丁起点 4，其它首字节返回 0。
- `controller.entrypoint-launch`：完整 run 工作流，验证 ready 先于 `main`、事件守恒、
  finalized、目标退出码 0 与 trace 回读。hardened preset 下目标带 `/CETCOMPAT`，走
  `endbr64` 保留路径。
- `controller.entrypoint-rollback`：
  - 缺少 bootstrap 导出的 agent 镜像在接触目标内存前被拒绝，目标从未运行。
  - 不可达 pipe 强制 stub ready 超时：stub 仍恢复入口字节并跳回原入口，目标以退出码 5
    （`ready=0` 与预期不符）证明其以恢复的原始入口完整跑完。
- CLI e2e 增加 `run --inject-method entrypoint-code` 覆盖；`attach` + `entrypoint-code`
  由配置校验以退出码 1 拒绝。

## 5. 已知限制

- 仅支持 suspended launch；attach 使用 `remote-thread` 或 `thread-hijack`。
- 入口点补丁为 12 字节绝对跳转，要求入口函数前 12 字节不属于会被其它代码相对寻址的
  数据（常规 PE 入口点满足）。
- 与 `thread-hijack` 相同的 XSTATE 限制：stub 恢复 XMM0-15/MXCSR，不覆盖 YMM/ZMM 高位；
  进程入口点处于 CRT 启动前，实际不使用 AVX 状态，风险可忽略。
