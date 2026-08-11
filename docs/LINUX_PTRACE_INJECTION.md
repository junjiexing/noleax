# ptrace 注入（Linux attach）

> 注入方式：`ptrace`，仅 `attach`
> 状态：已实现（Linux 移植 M6）

## 1. 目的与适用范围

attach 没有环境变量通道，LD_PRELOAD 不适用。ptrace 是 Linux 下向运行中进程注入 agent
的唯一现实对应物（等价 Windows 的 remote-thread/thread-hijack）。校验与权限：
`ptrace_scope=0/1` 时同用户子进程可注入；更严格时需要 `CAP_SYS_PTRACE`；doctor 的
`ptrace-scope` 检查项给出当前状态。

## 2. 流程（三段式）

1. **占据**：枚举 `/proc/PID/task` 全部线程 `PTRACE_SEIZE` + `PTRACE_INTERRUPT`
   （枚举期间新出现的线程反复补抓直到一轮无新增；中途退出的线程按 ESRCH 跳过）。
2. **选线**：注入 stub 只跑在"安全点"线程上——优先处于 syscall 阻塞中的线程；RIP 落在
   ld.so 映射内的线程直接排除（loader 锁死锁风险，对应 Windows thread-hijack 的
   事故教训）。找不到安全线程即报错，不强行注入。
3. **执行**：借用目标 libc 的 `syscall; ret` gadget 先 `mmap` 一页 RWX stub 页
   （单步执行完成）；stub 页内写入路径与参数后分两次调用——`dlopen(agent.so,
   RTLD_NOW|RTLD_LOCAL)`，然后 `noleax_agent_attach_bootstrap(params)`；每次调用以
   `int3` 回到控制器。两次之间控制器从 `/proc/PID/maps` 取 agent 基址，按文件内
   dynsym 偏移换算 bootstrap 的运行时地址。

stub 为 37 字节：`and rsp,-16; movabs rdi,arg1; movabs rsi,arg2; movabs rax,func;
call rax; int3`。所有线程的原始寄存器（含 flags）在每条路径上恢复并 detach；stub
页有意保留（一页，文档化）；不触碰 FP/向量态（选线规则使其实际不受影响）。

## 3. syscall 重启陷阱（实测发现）

被中断的线程若停在 `rax = -ERESTART_RESTARTBLOCK` 的 syscall 阻塞点，直接恢复 `rax`
并改 RIP 会让内核把 RIP 回退 2 字节"重启"系统调用——stub 从 `入口-2` 处执行即崩溃。
注入侧在改向时写 `orig_rax=-1` 并清掉 ERESTART 值；保存的原寄存器对在 detach 前恢复，
被中断的 syscall 按原始 RIP 正确重启。stub 执行期的 SIGSEGV/SIGILL/SIGBUS/SIGFPE 立即
失败并报出错位 RIP/地址，不再空转到超时。

## 4. bootstrap 与会话

attach 没有 env 通道，参数经 `AttachBootstrapParameters`（固定 ABI：socket 名、会话
token、控制器 PID、超时）写入 stub 页，`noleax_agent_attach_bootstrap` 在目标内拉起
会话 worker，之后的握手/状态机与 LD_PRELOAD 路径完全一致
（[LINUX_LAUNCH_INJECTION.md](LINUX_LAUNCH_INJECTION.md) §3）。

attach 盲期语义照搬 Windows：`capture_kind=kAttach` → scope
`preexisting_allocations_unknown`，分析输出标记、退出码 2。agent 在 worker 内吞掉所有
会话异常——控制器在注入后死亡绝不能终止目标进程。

## 5. 已知边界

- 一页 RWX stub 页留在目标地址空间（munmap 需第三次 stub 往返，收益不成比例）。
- FP/向量寄存器不保存（选线规则避开使用中的浮点状态；文档化限制，与 Windows
  XSTATE 注记同类）。
- 静态 TLS 盈余：agent 以 initial-exec TLS 编译，迟 dlopen 依赖 glibc 的静态 TLS
  盈余区；盈余耗尽的目标（极端嵌套 dlopen 场景）注入失败并报错。
- `ptrace_scope=2/3`、seccomp 拦截 ptrace 的容器内目标：EPERM，按提示提权或调整策略。

## 6. 验证

- `tests/integration/linux_ptrace_injector_test.cpp`：对长运行 fixture 注入 → 握手 →
  StartCapture（kAttach）→ QueryStatus（kCapturing 且 observed>0）→ drain/finalize →
  目标完整退出；trace 读出 `preexisting_allocations_unknown=true`、正常 end-of-trace。
  5/5 重复稳定。
- CLI 实证：attach 到循环分配目标，`--capture-duration` 到点停止后目标继续运行，
  事件计数正确，退出码 2。
