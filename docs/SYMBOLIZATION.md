# Noleax 离线符号解析


## 1. 范围

`OfflineSymbolizer` 将 trace 中记录的模块和绝对地址解析为 module+offset，以及可用时的
symbol+offset。Windows 实现使用 DbgHelp；DbgHelp 只在 analyzer 进程中调用，不进入目标进程或
hook replacement。

符号化提供独立符号服务；`TraceMetadata` 已将 trace 中的 ModuleLoad/Unload、StackDefinition
和 API registry 装配为 `noleax analyze` 共用的 filter/presentation resolver。CLI 因而可以直接从
trace 输出真实 module+offset，并在匹配映像/PDB 可用时输出 symbol+offset。

非 Windows 平台保留相同接口，注册模块时返回 `unsupported_platform`。Linux/macOS 的实现留待后续。

## 2. 输入模型

每个模块 generation 使用一个非零 `module_id`，并携带：

- trace 中的原始加载基址和 PE 映像大小；
- 离线映像路径；
- 可选 PE identity：timestamp、checksum、image size；
- 可选 PDB identity：16 字节 CodeView GUID 和 age。

同一路径或同一历史基址可以出现多个 generation，只要 `module_id` 不同。frame 必须位于所注册
模块的半开区间 `[base_address, base_address + image_size)`；越界地址会被拒绝，不猜测所属模块。

## 3. 解析流程

1. 校验 module ID、地址范围、映像大小和 identity。
2. 检查离线映像是否存在，并使用用户明确提供的本地 search path 或 symbol server 初始化
   DbgHelp。
3. 在该 symbolizer session 的合成地址空间中为模块分配唯一基址，避免历史模块基址复用造成
   DbgHelp 冲突。
4. 加载映像后比较 PE/PDB identity 和 DbgHelp mismatch 标志。
5. 将 trace 绝对地址转换为 module offset，再映射到合成地址进行符号查询。

无论符号是否可用，成功注册的模块都保留原始绝对地址、module basename 和 module offset。

## 4. 模块状态与回退

| 状态 | 含义 | 可用回退 |
|---|---|---|
| `symbols_loaded` | 已加载匹配的 PDB、DIA、CodeView 或 COFF 符号 | symbol+offset、module+offset、绝对地址 |
| `exports_only` | 只有 PE export 符号 | export+offset、module+offset、绝对地址 |
| `no_symbols` | 映像匹配，但 DbgHelp 没有可用符号 | module+offset、绝对地址 |
| `image_not_found` | 离线映像不存在或不可访问 | module+offset、绝对地址 |
| `image_identity_mismatch` | 映像大小或记录的 PE identity 不匹配 | 卸载符号，仅 module+offset 和绝对地址 |
| `pdb_not_found` | trace 要求的 PDB 未加载 | 可使用匹配映像的 export；始终保留 module+offset 和绝对地址 |
| `pdb_identity_mismatch` | PDB GUID/age 或 DbgHelp mismatch 标志不匹配 | 卸载符号，仅 module+offset 和绝对地址 |
| `load_failed` | DbgHelp 无法加载或查询模块 | module+offset、绝对地址，并保留系统错误码 |
| `unsupported_platform` | 当前平台尚无符号后端 | module+offset、绝对地址 |

identity mismatch 不会降级使用可能属于另一构建的符号。`pdb_not_found` 与 mismatch 不同：前者允许
继续使用已验证映像自身的 export。

## 5. Symbol path 与联网策略

- `symbols.mode` 控制解析策略：`auto` 尽可能解析，失败保留 module+offset 回退；`off` 完全不
  初始化 DbgHelp，注册模块直接报告 `no_symbols`，没有任何映像探测或网络访问；`required` 由
  `TraceMetadata` 在扫描时强制——任一模块结果不是 `symbols_loaded` 或 `exports_only` 即中止分析。
- `search_paths` 按用户顺序加入，转换为绝对路径。
- `symbol_servers` 只有用户显式配置时才加入：值带 `srv*` 前缀（大小写不敏感）时原样透传
  （可用 `srv*缓存目录*服务器地址` 指定下载缓存），否则补 `srv*` 前缀。
- 两者都未配置时，CLI 把 `_NT_SYMBOL_PATH`/`_NT_ALT_SYMBOL_PATH` 环境变量作为
  `raw_search_path` 传入（DbgHelp 惯例）；配置任一者则忽略环境变量。库本身不读取环境变量。
- path/server 条目不允许包含分号，server 必须是有效非空 UTF-8。
- 符号服务不自行管理下载缓存、凭据或代理；这些属于 CLI 集成和发布安全设计。

配置映射为 `symbols.paths` / `--symbol-path`、`symbols.servers` / `--symbol-server` 和
`symbols.mode` / `--symbols`，命令行覆盖配置文件。

## 6. 并发与生命周期

DbgHelp API 不是线程安全的。Noleax 使用进程级 mutex 串行化所有 session 的初始化、加载、查询、
卸载、清理和全局 option 修改；每次调用后恢复可恢复的原 option。安全策略会启用 DbgHelp 明确规定
为 process-sticky 的 `SYMOPT_SECURE`，该位在宿主进程内不能再关闭。每个 `OfflineSymbolizer` 另有
独立 session handle 和 module map。

module map 使用读写锁：多个查询可同时读取元数据，但进入 DbgHelp 后仍全局串行；注册和卸载独占
module map。锁顺序固定为 module map 在前、DbgHelp mutex 在后。对象析构仍要求调用方先停止针对该
对象的并发调用，这是普通 C++ 对象生命周期约束。

## 7. 符号枚举

`OfflineSymbolizer::enumerate_symbols(module_id)` 枚举已注册模块的全部符号（PDB
publics/globals，exports-only 模块为导出表），供 `noleax symbols` 使用。每个条目包含：

- `name`：存储名（C++ 符号为修饰名）。枚举期间在 DbgHelp 临界区内临时用
  `SymSetOptions(SymGetOptions() & ~SYMOPT_UNDNAME)` 关掉 undname 以拿到原始名，返回前恢复；
- `undecorated_name`：`UnDecorateSymbolNameW(UNDNAME_COMPLETE)` 的结果，失败时回退为
  `name`（C 符号两者相同）；
- `rva`：`Address - dbghelp_base`（模块合成基址相对偏移）；
- `size`：DbgHelp 报告的字节数，未知为 0；
- `tag`：SymTagEnum 原值，kind 归类（function/data/public/export/other）由 symbol_listing
  模块完成。

模块没有可用符号（`dbghelp_loaded == false`）或在非 Windows 平台时返回空 vector。锁序与第 6
节不变：module map 的 shared_lock 在前，DbgHelp mutex 在后；回调内不抛异常穿越 DbgHelp 栈帧。

`SYMOPT_EXACT_SYMBOLS`（所有 DbgHelp 调用统一启用）会在模块加载时抑制导出表回退：无 PDB 的
模块因此报告 `no_symbols` 而不是 `exports_only`。trace 分析保持这一严格行为；
`SymbolizerOptions::allow_export_symbols`（默认 false，仅 `noleax symbols` 启用）在加载该
模块时临时清掉 EXACT_SYMBOLS（option guard 析构时恢复），使导出表回退生效、模块报告
`exports_only`，其符号的 kind 一律归为 `export`。

## 8. 测试验证

Windows 组件测试使用带完整 PDB 和导出函数的专用 DLL，覆盖：

- 匹配 PDB 的真实函数名解析；
- 符号枚举：名称与 RVA 一致性、C 符号的反修饰恒等、无符号模块返回空；
- 记录的 PE/PDB identity 匹配与不匹配；
- 默认无隐式 symbol server 时的 PDB 缺失；
- 映像缺失、地址越界、重复/非法 module ID 和非法 path；
- 多线程并发 frame resolve；
- Debug/Release 构建。

符号化不替代 hook 安全测试；符号查询始终位于离线 analyzer，不能在 hook 热路径中调用。

## 9. Linux 后端（ELF 符号）

> 状态：已实现（Linux 移植 M5）。后端为内置 ELF64 符号读取器
> （`src/analyzer/elf_image.cpp`），无外部依赖；`unsupported_platform` 不再出现于
> Linux 录制的 trace。

- 覆盖：`.symtab` 全量符号表优先（`symbols_loaded`）；只有 `.dynsym` 时导出符号兜底
  （`exports_only`）；两者皆无（strip 彻底）为 `no_symbols`。DWARF 行号不在本期——输出
  模型消费的是函数级 `module!symbol+offset`，dynsym/symtab 已够。
- 分离调试文件（`.gnu_debuglink`）：运行时映像无 `.symtab` 但带 well-formed
  `.gnu_debuglink` 节时，按固定顺序搜索 companion——映像同目录、同目录 `.debug/`
  子目录、`--symbol-path` 各目录、`/usr/lib/debug/<映像绝对路径>/`。候选必须通过身份
  校验才会使用：优先比对 debuglink 存储的 **GNU CRC32**（zlib/IEEE 多项式，与 trace
  线格式的 CRC32C 无关）；两侧都有 Build ID 时另要求 Build ID 一致。全部候选缺失时
  退回 `.dynsym`（`exports_only`）；候选存在但校验失败时状态为
  `debug_identity_mismatch`（仍退回 `.dynsym` 解析，`--symbols required` 下失败）。
  地址换算始终以运行时映像的 load layout 为准，符号表取自 debug ELF。
- 地址换算：agent 记录的模块基址 = load_bias + min(PT_LOAD p_vaddr)，后端查表用
  `绝对地址 - base + min_vaddr`；RVA 输出为 `st_value - min_vaddr`。PIE 主程序与共享库
  同一公式。
- 名称：C++ 符号经 `abi::__cxa_demangle` 反修饰（对齐 Windows 的 UnDecorateSymbolName
  行为）；同名别名（如 `__libc_malloc`/`malloc`）按"尺寸包含优先、非局部绑定优先、
  名字典序"确定性选择。
- 身份校验：v1 按 trace 记录的**路径**打开映像；ELF build-id 的落位（ModuleLoad 记录
  版本 2）是后续的格式治理项——当前没有身份不匹配检测，分析他机/他构建的模块时结果
  可能张冠李戴，与 PDB 缺失场景同级对待。`image_identity_mismatch`/
  `pdb_identity_mismatch` 在 Linux 后端不产生（`.gnu_debuglink` companion 的校验是
  独立机制，见上）。
- `--symbol-server`/`srv*` 与 `_NT_SYMBOL_PATH` 回退是 Windows 概念，Linux 后端忽略；
  `--symbol-path` 参与 split-debug companion 搜索。debuginfod 本期不做。
- 主程序模块路径：agent 快照时 readlink `/proc/self/exe` 取真实路径（M5 修正——否则
  分析进程会把 `/proc/self/exe` 解析成 noleax 自身映像）。
