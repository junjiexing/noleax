# Custom Symbol Hook 设计

> 状态：已实现。本文档是该功能的权威说明；§10 记录实现相对原设计的偏差与细化。

## 1. 目标

让用户声明第三方 allocator(jemalloc/mimalloc/tcmalloc/自研)的分配函数为 hook 点,纳入与内置
9 个 API 相同的事件记录、泄露聚合与分析体系,解决"第三方 allocator 只做大块 VM 申请、内部切分
不可见"的盲区(HOOK_API_MATRIX.md §5)。

范围刻意保持声明式:hook 点由用户用 TOML/CLI 声明,符号解析支持导出表、PDB 和 RVA 三种定位,
参数语义通过参数位映射表达。不引入脚本语言。

## 2. 声明模型

每个 hook 点声明一个模块和最多三个函数角色:alloc、realloc、free。

```toml
[[custom_hooks]]
module = "myalloc.dll"

# 三种定位方式,同一角色三选一:
alloc = "my_malloc"                  # 导出表符号(agent 内解析)
alloc_pdb = "myalloc!internal_alloc" # PDB 符号(controller 侧 DbgHelp 解析为 RVA)
alloc_rva = "0x12340"                # 直接 RVA(十六进制)

free = "my_free"
realloc = "my_realloc"

size_arg = 0        # alloc/realloc 的 size 参数位,默认 0
ptr_arg = 0         # realloc/free 的指针参数位,默认 0
# result_arg = 1    # 结果经 *(void**)argN 返回时设置;默认结果取 rax
# kind = "calloc"   # alloc 语义为 count×size 时声明(配 count_arg)
# count_arg = 0
# free_size_arg = 1 # free 自带 size 时直接记账
forced = false      # 序言不可重定位时是否允许 forced relocation,默认 false
wait_module = "0s"  # 安装时模块未加载的等待上限;0 = 立即失败,默认 0
```

共享的 `size_arg`/`ptr_arg`/`count_arg` 表达不了各角色参数位不一致的签名(如 C++ 成员
allocator:`this` 占参数位 0,`Malloc(size, align)` 的 size 在参数位 1)。每角色参数位
(仅 TOML)覆盖这一形态:

```toml
[[custom_hooks]]
module = "myalloc.dll"
alloc = "my_malloc"
realloc = "my_realloc"
free = "my_free"
# 任写一个每角色键即整体启用每角色形态,未写的槽位默认 0;此时 legacy 的
# size_arg/ptr_arg/count_arg 必须全部缺省(或为 0),混写在配置校验期报错。
alloc_size_arg = 1    # alloc 的 size 参数位(calloc 时为其元素大小位)
# alloc_count_arg = 2 # alloc 的 count 参数位(配 kind = "calloc")
realloc_ptr_arg = 1   # realloc 的指针参数位
realloc_size_arg = 2  # realloc 的 size 参数位
free_ptr_arg = 1      # free 的指针参数位
```

legacy 键按下述规则展开为每角色槽位:`alloc_size_arg = size_arg`、
`realloc_size_arg = size_arg`、`realloc_ptr_arg = ptr_arg`、`free_ptr_arg = ptr_arg`、
`alloc_count_arg = count_arg`。`result_arg`/`free_size_arg`/`forced`/`wait_module` 两种
形态共用,语义不变。

CLI 重复选项(与 TOML 数组替换语义一致):

```
noleax attach --custom-hook "myalloc.dll:alloc=my_malloc,free=my_free" ...
noleax attach --custom-hook "myalloc.dll:alloc_pdb=myalloc!internal_alloc,free_rva=0x1a210,size_arg=0" ...
```

规则:

- `alloc` 与 `free` 必填;`realloc` 可选。
- 同一模块重复声明、同一角色多种定位并存、参数位越界(x64 最多 8 个参数位:0–3 为
  rcx/rdx/r8/r9,4–7 为栈槽)都在配置校验期报错。
- `forced = true` 走 `install_fast_forced`;默认 checked relocation,不可重定位即安装失败并给出
  明确错误。

## 3. 解析流水线

三种定位最终都归结为 `module 基址 + RVA`:

- **导出表符号**:agent 在目标进程内读取模块 PE 导出表(只读,无锁,不调 loader API),
  名字转 RVA。模块未加载时按 `wait_module` 轮询(100ms 粒度),超时返回明确错误。
- **PDB 符号**:controller 侧用现有 DbgHelp 离线符号设施(沿 `symbols.paths`/`symbols.servers`/
  `_NT_SYMBOL_PATH` 的既有解析规则)把 `module!name` 解析为 RVA。**只依赖模块映像文件**:
  attach 取远端模块路径;run/launch 按目标 exe 同目录与 PATH 搜索顺序定位文件;patch
  standalone 见下方"standalone 的烘焙合同"。解析失败(无 PDB、符号未找到、内联函数
  无独立代码)在安装前报明确错误。
- **RVA**:直接使用,合法性(落在模块 .text 内)由安装期检查。
- **ELF 符号(`<role>_sym`,仅 Linux)**:任意 symtab/dynsym 符号名。live 路径由
  controller 侧对磁盘映像解析并烘焙为 RVA(与 PDB 同一合同);Linux standalone 没有运行期
  controller,由 agent 在安装期自行解析——流式扫描模块磁盘映像的 `.symtab`,无可用
  `.symtab` 时回退 `.dynsym`,再退到 `.gnu_debuglink` 伴生调试文件(搜索顺序:映像同目录、
  其 `.debug/` 子目录、`/usr/lib/debug/<映像绝对路径>/`;伴生文件须通过 GNU CRC32 与
  Build ID 双重校验),命中后按"映射基址 + (st_value − 最小装载地址)"换算为运行时地址。

解析结果经 StartCaptureRequest(见 §5)传入 agent;直写(standalone)模式 agent 自行读取
TOML 中的同一声明,此时 PDB 解析仍由写出该配置的 controller 提前完成并烘焙为 RVA。
Linux standalone 的 `_sym` 定位是唯一的例外:它以 kElfSymbol 定位随配置直达 agent,由
agent 按上条规则在目标进程内解析,无需烘焙。

**standalone 的烘焙合同**:patch standalone 没有运行期 controller,PDB 解析在 `noleax patch`
执行时完成——对磁盘上的模块映像解析后,在输出副本旁写出**已解析的** `noleax-agent.toml`
(`alloc_pdb` 等替换为 `alloc_rva`,并记录模块映像 identity)。patched 副本运行时 agent 只读
RVA。运行期 TOML 中出现未解析的 PDB 符号(env 或手工编写的配置)时 agent 启动直接报错,
提示经 `noleax patch` 烘焙或改用导出符号/RVA,不静默忽略。安装期先校验记录的映像 identity
(timestamp/checksum/image size),与运行机器上的模块不一致时报错,不错位 hook。注意
standalone 下 agent 在目标 main 运行前安装,bootstrap stub 会等 agent ready;`wait_module`
无法等待一个由 main 才加载的模块——此类模块必须由目标静态导入(loader 在入口前加载)或
由其他先行模块加载。

## 4. 通用 replacement 与参数映射

不为任意签名生成代码。三个签名族各一个通用 replacement(`generic_alloc`/`generic_realloc`/
`generic_free`),行为对齐内置 Rtl\* adapter:replacement lifecycle 计数与路由、guard 递归抑制、
min_size 过滤、栈捕获、无锁队列发布。每个 hook 点一个描述符块(api_id、original trampoline、
参数位、队列指针),replacement 从描述符取上下文,代码一份、状态按点分离。

**为什么用 replace 而不是 hoox 的 attach(InvocationListener)**:attach 每次调用要保存/恢复
全部 CPU 上下文并做监听分发,开销比"读固定寄存器"高一个量级,不适合进程最热的分配路径;
noleax 需要的 lifecycle 计数、递归抑制、SEH 异常观察、LastError 保留在 attach 上都要自己再包
一层;且 attach 的执行路径穿过 hoox 的 dispatch trampoline,不在 `.nlxhk` 段内,rendezvous 的
排空证明会失效。参数位在安装期已确定,运行时读固定槽位只有两三条指令,args[] 是编写期便利,
对本设计没有运行时价值。内置 Rtl\* hook 不用 attach 是同一组理由(见 HOOK_BACKEND.md)。

参数映射(x64 Windows ABI / System V AMD64 通用 replacement 均声明 8 个指针槽位):

- alloc:结果取 `rax`;size 取第 `alloc_size_arg` 个参数(`kind = "calloc"` 时语义 size =
  `alloc_count_arg` × `alloc_size_arg`,带溢出检查,溢出按失败事件记录)。
- realloc:指针取第 `realloc_ptr_arg` 个、size 取第 `realloc_size_arg` 个;结果取 `rax`。
- free:指针取第 `free_ptr_arg` 个参数;返回值忽略。

TOML 的 legacy 键(`size_arg`/`ptr_arg`/`count_arg`)按 §2 的规则展开为上述每角色槽位;
CLI `--custom-hook` 只有 legacy 键。参数位 0–3 读 rcx/rdx/r8/r9(Windows)或
rdi/rsi/rdx/rcx(SysV 前四槽);4–7 读入口栈槽。

非标准签名的处理(全部为声明式映射,不引入脚本语言):

- **参数位置不同**:`my_alloc(Arena*, size)` 用 `size_arg = 1` 之类直接表达;多余的参数
  (flags/alignment/arena)不影响语义提取。
- **结果在 out-param**:`result_arg = N`(默认不设,结果取 rax)。replacement 在 original 返回后
  从 `*(void**)argN` 读取结果指针,如 `posix_memalign(out, align, size)` 用
  `size_arg = 2, result_arg = 0`。
- **calloc 族**:`kind = "calloc"` 时语义 size = `count_arg` × `size_arg`(带溢出检查,溢出按
  失败事件记录),如 `je_calloc(count, size)`。
- **free 自带 size**:`free_size_arg = N`(如 `je_sdallocx(ptr, size, flags)`、
  `mi_free_size(ptr, size)`)直接以该值记账,不查 generation tracker——对 slab allocator 更准。

明确不支持的形态(配置校验报错,不静默猜测):参数为浮点/向量/按值结构体;参数位超出 0–7;
结果写入非指针 out-param;varargs。语义无法提取时 hook 无意义。
全部通用 replacement 编入 `.nlxhk` 段(rendezvous 硬要求),安装/卸载/quiescence 走现有
adapter 基础设施;uninstall/reinstall/unload-on-stop 与内置 hook 行为一致。

事件语义:

- alloc → AllocationEvent;free → FreeEvent;realloc → ReallocationEvent(新 generation)。
- `allocation_id = (api_id << 40) | counter`,counter 每 hook 点从 1 递增,64 位内不与内置 id
  冲突;free/realloc 按地址经 generation tracker 匹配,泄露分析语义与内置 API 相同。
- 第三方函数内部再调底层被 hook API(如 my_malloc 内部调 RtlAllocateHeap)由 guard 的
  hook_depth 递归抑制,不重复记录。

## 5. trace 与 agent 协议

- **CustomHookDefinition 记录**(trace 新记录类型):`{api_id, module_name, label}`。label 为
  符号名或 `module+0x<rva>`。首个自定义事件前写出。api_id 从 `0x1000` 起按声明顺序分配,
  一次捕获内稳定。老 analyzer 跳过未知记录并显示 `api-<id>` 兜底,新 analyzer 解析出真实名。
- **CustomHookFailure 记录**(minor 3):`{module, role, reason, detail}`。某个 hook 点安装
  失败时逐条写出(紧接 CustomHookDefinition 之后),捕获降级继续;analyzer 据此列出失败明细
  并设置 `custom_hook_install_failed`(bit 10),live 与直写两种模式行为一致。
- `EventMetadata.api_name/api_module`、`--api` 过滤、stacks 聚合 apis 展示全部自然扩展到自定义
  名称。
- **StartCaptureRequest** 增加 `custom_hooks` 数组(每元素:module、三个角色的定位与启用位、
  每角色参数位 alloc_size_arg/alloc_count_arg/realloc_ptr_arg/realloc_size_arg/free_ptr_arg、
  result_arg、free_size_arg、calloc、forced、wait_module_ms、label),IPC 字段级编码。
  该数组自 ABI 3 起存在(2 → 3 由本特性引入);ABI 4 → 5 把共享的
  size_arg/ptr_arg/count_arg 换成每角色参数位并新增 kElfSymbol 定位(当前 ABI 版本以
  [IPC_PROTOCOL.md](IPC_PROTOCOL.md) 为准)。

## 6. 配置校验

- TOML/CLI 语法、角色必填、定位互斥、参数位 0–7、重复模块、wait_module 时长解析。
- `--custom-hook` 仅 run/attach 有效(patch/doctor/analyze 下报错)。
- 安装期失败(模块超时未出现、导出/PDB/RVA 解析失败、checked relocation 拒绝)按 hook point
  降级:只回滚失败的 hook 点,其余 hook 点与内置 profile 照常安装,捕获继续;失败明细写入
  trace 的 CustomHookFailure 记录并置 completeness `custom_hook_install_failed`,退出码由
  trace 完整性驱动为 2。目标进程的既有状态不被破坏。

## 7. 测试

- 单元:声明解析(TOML/CLI/校验全部分支)、参数位到寄存器/栈槽的映射表、CustomHookDefinition
  编解码、analyzer 名字解析与过滤、老 analyzer 跳过未知记录。
- fixture allocator DLL:导出 `my_malloc/my_realloc/my_free`(内部调 RtlAllocateHeap),另有不导出
  的内部函数供 PDB/RVA 定位(带 PDB 构建)。
- 集成:e2e 三种定位方式各捕获一轮,断言自定义事件名、次数、字节数、leaks 归属与聚合展示;
  递归抑制不重复计数;缺模块/缺导出/缺 PDB/不可重定位错误路径;forced=true 的序言兼容;
  wait_module 在目标中途加载模块后成功;与 unload-on-stop/reinstall 的组合。
- 回归:全量 ctest、quiescence-race、clang-tidy、clang-format。

## 8. 文档

CLI.md、CONFIG.md、QUICKSTART.md(示例)、HOOK_API_MATRIX.md §5 更新、TRACE_FORMAT.md
(新记录类型)、ROADMAP.md(移除该项)、本文档随实现同步为最终说明。

## 9. 风险与对策

- **参数映射错误导致语义错乱**:声明期校验 + e2e 对 fixture 的精确断言;文档明确"映射由用户
  对目标函数签名负责"。
- **forced 被当常规开关用**:文档明确 forced 仅在 checked 拒绝时评估,且目标序言兼容性由
  用户承担。
- **DbgHelp 解析在 controller 侧的耗时**:一次性解析,结果烘焙为 RVA;CI 有符号缓存测试覆盖。
- **wait_module 的轮询盲区**:模块加载到下一次轮询 tick(100ms)之间发生的调用必然错过——
  这是轮询式等待的固有限制。需要捕获"加载后第一批调用"时,应让目标在加载后给 agent 留出
  安装窗口(如先 attach 到已加载模块的进程,或目标侧配合停顿)。
- **wait_module 超时按 hook point 降级**:超时只放弃该 hook 点(记录 module_not_loaded),
  捕获以其余 hook 继续并通过 completeness issue 与退出码 2 暴露,不再使整个 capture 启动
  失败。需要"装不上就不捕获"的旧语义时,应在 analyze 侧检查
  `custom_hook_install_failed` 后再采信结果。
- **PDB 与加载映像不一致**:DbgHelp 按 PDB identity 校验(沿用既有 symbolizer 的 identity
  检查),不匹配即报错而不是错位 hook。

## 10. 实现与设计的差异(最终说明)

按原设计实现时发现的具体化与偏差,均为收敛性决策:

1. **描述符绑定机制**:原设计"replacement 从描述符取上下文,代码一份"。MSVC x64 没有
   naked function 和 inline asm,无法通过寄存器把描述符交给一份共享代码并在编译器序言之前
   读取。实现为:三个角色各一个**通用实现函数**(`custom_alloc_impl`/`custom_realloc_impl`/
   `custom_free_impl`,逻辑一份,`__declspec(noinline)`),外加**固定的每点锚定 thunk 池**
   (32 点 × 3 角色,宏展开):thunk 以 `slot*` 为显式参数尾调实现函数。thunk 与实现函数
   都编入 `.nlxhk`,rendezvous 语义不变——生命周期计数在实现函数首语句生效,thunk 与被调
   实现的序言都处于 rendezvous 覆盖的"未计数窗口"。这保留设计意图(逻辑一份、状态按点),
   代价是每点两条指令的固定锚点。相应地声明上限为 **每次捕获 32 个 hook 点**(原设计未
   设上限),配置/IPC 两侧均校验。slot 单调分配、不回收,放弃 teardown 时按内建 adapter 同
   款策略滞留以保安全。
2. **replacement 读取参数的方式**:x64 ABI 下通用 replacement 声明 8 个指针参数
   (`PVOID a0..a7`),参数位 0–3 自然落在 rcx/rdx/r8/r9,4–7 落在入口栈槽,与设计的映射
   表一致;free/realloc 的 rax 原样透传回调用方。`result_arg` 在 original 返回后读取
   `*(void**)argN`。
3. **IPC 元素的字段构成**:按 §5 的要素实现(module、三角色定位与启用位、参数位、
   forced、wait_module_ms、label),其中定位携带导出名或 RVA 之一(agent 侧才能解析导出
   表);另增加 image_identity 可选字段(原 §5 未列):standalone 烘焙合同要求的
   timestamp/checksum/image size 校验因此能统一作用于 live(IPC)与 standalone(TOML)
   两条路;live 路径下 controller 解析 PDB 时也一并下发 identity。ABI 已按要求 2→3。
4. **free_size_arg 的记账**:参数映射、校验、replacement 取值均已接线,size 随原始事件携带;
   但当前 trace 的 FreeEvent 没有 size 字段,值不落盘,分析侧记账仍按 generation。若后续
   需要按 free-size 记账,需在 trace 层再加一个 minor 扩展。
5. **label 取值**:按 alloc 角色的符号名(或 `module+0x<rva>`)生成;同一 hook 点的
   alloc/realloc/free 事件共享该 api_id 与 label,与原设计"每 hook 点一个 api_id"一致。
   烘焙后的 standalone 配置中 PDB 定位已替换为 RVA,agent 侧 label 相应为
   `module+0x<rva>` 形式;live 路径(label 在 controller 侧按原始声明生成并随 IPC 下发)
   保留符号名。
6. **agent 侧模块定位**:导出名在 agent 内经只读 PE 导出表解析(forwarded export 明确
   报错);RVA 定位在安装期校验落在可执行节内。identity 不一致、模块缺失、导出缺失按
   hook point 降级:失败点回滚并写入 CustomHookFailure 记录,捕获继续并以
   `custom_hook_install_failed` + 退出码 2 暴露;PDB 未解析(standalone TOML 中出现
   `_pdb`)仍是启动期硬错误(agent 无法从中恢复出可安装的定位)。
7. **api_id 命名解析顺序**:内建注册表 → trace 内 CustomHookDefinition → `api-<id>` 兜底,
   与老 minor reader 跳过该记录并显示兜底名的兼容语义一致。
8. **每角色参数位与 kElfSymbol(ABI 4 → 5)**:原设计的共享 `size_arg`/`ptr_arg`/`count_arg`
   无法表达各角色参数位不一致的签名(C++ 成员 allocator 的 `this` 占参数位 0:
   `Malloc(size, align)` 的 size 在 1,`Realloc(ptr, size, align)` 的指针/size 在 1/2,
   `Free(ptr)` 的指针在 1)。线上模型改为每角色槽位
   (alloc_size_arg/alloc_count_arg/realloc_ptr_arg/realloc_size_arg/free_ptr_arg),TOML 的
   legacy 键保留并按 §2 规则展开,混写在配置校验期报错;agent 的通用 replacement 按角色
   读各自槽位,`result_arg`/`free_size_arg` 语义不变。定位枚举新增 kElfSymbol(仅 Linux),
   符号名复用角色的 export_name 字段承载:Linux standalone(`LD_PRELOAD` +
   `NOLEAX_AGENT_CONFIG`)由此支持 `[[custom_hooks]]` 全量声明——导出符号、`_sym`、RVA
   均在 agent 安装期解析(`_pdb` 为 Windows 专有,出现即拒绝配置);解析失败沿用按
   hook point 降级并写 CustomHookFailure 的既有模型。
