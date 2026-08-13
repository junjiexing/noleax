# ptrace 注入（Linux attach）

> 注入方式：`ptrace`，仅 `attach`
> 状态：已实现（Linux 移植 M6）

## 1. 目的与适用范围

attach 没有环境变量通道，LD_PRELOAD 不适用。ptrace 是 Linux 下向运行中进程注入 agent
的唯一现实对应物（等价 Windows 的 remote-thread/thread-hijack）。校验与权限：
`ptrace_scope=0/1` 时同用户子进程可注入；更严格时需要 `CAP_SYS_PTRACE`；doctor 的
`ptrace-scope` 检查项给出当前状态。

## 2. 流程（三段式 + 停核窗口，H1-B 起）

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
call rax; int3`。所有线程的原始寄存器（含 flags）在每条普通路径上恢复并 detach；stub
页有意保留（一页，文档化）；不触碰 FP/向量态（选线规则使其实际不受影响）。

**停核窗口全程持有（H1-B）**：bootstrap 不再把握手/安装甩给目标内的新线程——
`noleax_agent_attach_bootstrap` 在被劫持线程上同步完成 connect → 握手 → StartCapture →
全部 hook 安装（含退出钩子）→ 回执 CaptureReady 后才返回，injector 随后才恢复寄存器并
detach。任何业务线程都不可能在运行中撞见写了一半的 prologue；controller 侧把 `inject`
放在 worker 线程上、主线程并发跑握手（两个错误通道都保留，握手错误携带 agent 自己的
失败细节，优先上报）。

**与 hoox 的 external suspension 合同**：bootstrap 全程把 hoox 的线程局部
`hoox_memory_set_external_thread_suspension` 置位（经 `HookBackend::set_external_thread_suspension`
+ agent 内的 RAII scope，所有出口都清除）。置位期间 hoox 跳过进程内停核（peer park）： park
信号发往 ptrace 停核线程会一直 pending 到线程恢复（detach 之后），park 等待只会耗尽预算并把
patch 打进 hx_abort；对屏蔽该信号的线程同理。这正是事故现场（SIGABRT）的根除点。
patch 写入本身仍在全部线程被 ptrace 冻结时完成。

**patch 窗口撤离扫描**：external suspension 同时跳过 hoox 的"停核点 PC 落在被覆盖序言内"
防护扫描（该扫描依赖 park handler 记录的运行时 PC），所以 injector 在占据后、任何 patch
之前自己做这一步：对每条被停线程，若其 rip 落在任一将被改写的符号区间（内建 registry
符号 + `exit`/`_exit`，以及按声明解析出的 custom hook 目标）的 `(symbol+1, symbol+33)`
窗口内，则把它单步执行出窗口（单步跑的是线程自己的真实指令；步进后的寄存器成为新的
saved_regs，detach 恢复点因此落在窗口之外）。窗口取 32 字节保守上界（hoox x86-64
fast hook 最多覆盖约 20 字节；窗口从 +1 起算——停在入口字节上的线程两个方向都安全）。
单步 64 次仍不出窗口（窗口内自旋）则按普通失败处理：此时尚未写任何 patch，恢复 + detach
安全。

## 3. syscall 重启陷阱（实测发现）

被中断的线程若停在 `rax = -ERESTART_RESTARTBLOCK` 的 syscall 阻塞点，直接恢复 `rax`
并改 RIP 会让内核把 RIP 回退 2 字节"重启"系统调用——stub 从 `入口-2` 处执行即崩溃。
注入侧在改向时写 `orig_rax=-1` 并清掉 ERESTART 值；保存的原寄存器对在 detach 前恢复，
被中断的 syscall 按原始 RIP 正确重启。stub 执行期的 SIGSEGV/SIGILL/SIGBUS/SIGFPE 立即
失败并报出错位 RIP/地址，不再空转到超时。

## 4. bootstrap 与会话

attach 没有 env 通道，参数经 `AttachBootstrapParameters`（固定 ABI：socket 名、会话
token、控制器 PID、超时）写入 stub 页。`noleax_agent_attach_bootstrap` 在被劫持线程上
同步跑完整个会话 bootstrap（H1-B 起）：握手、状态机与 LD_PRELOAD 路径完全一致
（[LINUX_LAUNCH_INJECTION.md](LINUX_LAUNCH_INJECTION.md) §3），返回 0 表示 CaptureReady
已发出、全部 hook 已安装；injector 的返回因此必然排在安装完成信号之后。返回值约定：
0=就绪，1=参数 ABI 不符，2=已 bootstrap 过，3=未捕获异常，4=会话/启动失败（细节经会话
通道的 ErrorResponse 先到 controller）。

attach 盲期语义照搬 Windows：`capture_kind=kAttach` → scope
`preexisting_allocations_unknown`，分析输出标记、退出码 2。agent 在 worker 内吞掉所有
会话异常——控制器在注入后死亡绝不能终止目标进程。

## 5. 超时与失败窗口

`injection.timeout`（默认 10 s）贯穿 占据→dlopen→bootstrap→握手→安装 全程（injector 内
不再有任何隐藏固定预算）。主 deadline 在 stub 执行中途耗尽时**不是**立即判死：被注入的
调用是有限的（connect 有界 + 安装有界），因此先给一个与配置等长的 grace 预算等它跑到
stub 的 int3——grace 内完成按普通结果处理（成功或普通错误都走既有的恢复 + detach）。
只有连 grace 也耗尽的 stub 才判定为 **wedged**：此时绝不能恢复该线程的保存寄存器（会把
仍在 agent 代码中的线程传送回劫持前的 rip = 内存损坏），injector 改为放弃整个 seizure
——不恢复任何寄存器、不 detach 任何线程、进程保持停核——并抛出与普通超时明显不同的
响亮错误：目标已不一致，必须重启。wedged 目标仍被 controller 进程的 ptrace 关系持有；
controller 退出后内核会解除停核，线程可能带着半个 bootstrap 继续——所以错误信息要求
重启目标，这是对事故场景的诚实失败而不是掩盖。

普通失败（占据失败、线程选择失败、dlopen 失败、bootstrap 返回非零、撤离扫描超时）全部
保持既有行为：恢复每条线程的原始寄存器（含被中断 syscall 按规则重启）并 detach。

## 6. 已知边界

- 一页 RWX stub 页留在目标地址空间（munmap 需第三次 stub 往返，收益不成比例）。
- FP/向量寄存器不保存（选线规则避开使用中的浮点状态；文档化限制，与 Windows
  XSTATE 注记同类）。
- 静态 TLS 盈余：agent 以 initial-exec TLS 编译，迟 dlopen 依赖 glibc 的静态 TLS
  盈余区；盈余耗尽的目标（极端嵌套 dlopen 场景）注入失败并报错。
- `ptrace_scope=2/3`、seccomp 拦截 ptrace 的容器内目标：EPERM，按提示提权或调整策略。
- custom hook 的 `wait_module` 在停核窗口内等不到模块加载（没有任何线程在跑）；attach
  时对尚未加载的模块声明 hook 点会在窗口内等到其自身预算耗尽并按点降级，与
  standalone/run 的语义不同（那两类在活进程内等待是有效的）。

## 7. 验证

- `tests/integration/linux_ptrace_injector_test.cpp`：对长运行 fixture 注入 → 握手 →
  StartCapture（kAttach）→ QueryStatus（kCapturing 且 observed>0）→ drain/finalize →
  目标完整退出；trace 读出 `preexisting_allocations_unknown=true`、正常 end-of-trace。
  fixture 携带一个屏蔽 SIGRTMIN+6 的 peer 与一条持续 churn 的线程——park 信号被屏蔽的
  目标在旧模型下必崩（事故回归），在停核窗口模型下正常。
- 同一文件内的重复 attach/drain 循环（Release 100 轮 / Debug 25 轮，多线程 churn
  fixture）：零崩溃、每轮握手干净、finalize 落 kDormant、目标事后行为完整。
- fault 用例：agent 拒绝的 StartCapture（unload_on_stop）在 controller 侧报出阶段 +
  根因（hook-install 分类 + agent 消息），目标线程/寄存器完整（退出码与 batch 报告不变）。
- grace/wedged 用例：经 `NOLEAX_ATTACH_BOOTSTRAP_DELAY_MS` 测试接缝拉长窗口内
  bootstrap——超时后 grace 内完成按普通结果（恢复 + detach，目标无损）；超出 grace 判
  wedged，进程保持停核、报"必须重启"的错误，测试随后按文档动作杀目标并完成清理。
- CLI 实证：attach 到循环分配目标，`--capture-duration` 到点停止后目标继续运行，
  事件计数正确，退出码 2。
