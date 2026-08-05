# Noleax symbols:PE 符号枚举

> schema version:1(JSON `noleax.symbols` v1)

## 1. 范围

`noleax symbols` 枚举一个 PE 文件(exe/dll,x86/x64 均可)的符号并输出为表格或机器可读
文档。符号来源沿用 `OfflineSymbolizer`(DbgHelp):有匹配 PDB 时枚举 PDB 的
publics/globals,否则回退到 PE 导出表。命令只读离线映像,不启动、不注入任何进程。

枚举结果原样输出:同一地址同时存在 function 与 public 两条记录时两条都列,不做去重
合并。不做 DIA/私有符号(局部变量、行号)枚举。

## 2. 命令面

~~~
noleax symbols [options] file
~~~

| CLI | 配置键(`[symbol_listing]`) | 默认值 |
|---|---|---|
| `file`(operand,恰好 1 个) | `input` | 必填,必须存在 |
| `--format console\|json\|csv` | `format` | console |
| `--output PATH` | `output` | stdout;写文件时覆盖并自动创建父目录 |
| `--name PATTERN`(可重复) | `name`(数组) | 空 = 全部 |
| `--match-case` / `--no-match-case` | `match_case` | false(大小写不敏感) |
| `--kind KIND`(可重复) | `kind`(数组) | 空 = 全部 |
| `--fields a,b,c` | `fields`(数组) | 空 = 全部字段,固定顺序 |
| `--symbol-path PATH`(可重复) | `symbols.paths`(复用 `[symbols]` 段) | 空 |
| `--symbol-server URL`(可重复) | `symbols.servers`(同上) | 空 |

`--kind` 取值:`function`、`data`、`public`、`export`、`other`。`--fields` 取值:
`name`、`undecorated_name`、`rva`、`va`、`size`、`kind`。

`symbols.mode = off` 与本命令冲突(枚举必须经过 DbgHelp),配置校验报错。

## 3. 筛选语义

- 多个 `--name` pattern 之间是 OR;pattern 支持 `*` 与 `?`,同时匹配 `name` 与
  `undecorated_name` 两个字段,任一命中即保留。
- 多个 `--kind` 之间是 OR;name 与 kind 两个类别之间是 AND。
- 默认大小写不敏感(仅 ASCII 折叠);`--match-case` 改为精确匹配。
- 统计:`total` 是过滤前的枚举总数,`matched` 是过滤后的条数。

## 4. 字段

| 字段 | 含义 |
|---|---|
| `name` | PDB/导出表中存储的原始名(C++ 符号为修饰名) |
| `undecorated_name` | `UnDecorateSymbolNameW(UNDNAME_COMPLETE)` 的结果;C 符号与 `name` 相同 |
| `rva` | 相对映像基址的偏移,`0x` 前缀小写十六进制 |
| `va` | PE 可选头 ImageBase + rva,`0x` 前缀小写十六进制 |
| `size` | 字节数,十进制;未知为 0 |
| `kind` | `function`(SymTagFunction)/ `data`(SymTagData)/ `public`(SymTagPublicSymbol)/ `export`(exports_only 模块的全部符号)/ `other` |

`--fields` 同时控制 console 列、CSV 列和 JSON 符号对象的键,严格遵循选择(不强制保留
`name`)。缺省为全部六个字段,顺序固定为上表顺序。

## 5. 输出格式

### 5.1 console(默认)

~~~
noleax symbols
module: C:\...\foo.dll (image-size=123456 base=0x180000000)
symbols: symbols_loaded
filters: name=*alloc* (ignore-case); kind=function,public
fields: name, undecorated_name, rva, va, size, kind
total: 1234  matched: 42
name                   undecorated_name  rva      va           size  kind
?alloc@foo@@YAPEAX_K@Z foo::alloc        0x1a210  0x18001a210  128   function
~~~

头部依次是模块路径与映像信息、符号状态(`symbols_loaded` / `exports_only` /
`no_symbols`)、生效的筛选(无筛选显示 `filters: none`)、生效的字段、total/matched
统计,其后是按数据对齐列宽的表格。`symbols:` 行如实展示状态;`no_symbols` 时列表为空,
命令仍返回 0。

### 5.2 json

紧凑单行 JSON,schema 版本化为 `noleax.symbols` v1(见
[schema/noleax-symbols-v1.schema.json](schema/noleax-symbols-v1.schema.json),对根对象与
已定义对象禁止未知字段):

~~~json
{
  "schema": "noleax.symbols",
  "schema_version": 1,
  "module": {"path": "...", "status": "symbols_loaded", "image_size": 123456,
             "image_base": "0x180000000", "timestamp": "0x...", "checksum": "0x..."},
  "filters": {"names": ["*alloc*"], "match_case": false, "kinds": ["function"]},
  "fields": ["name", "undecorated_name", "rva", "va", "size", "kind"],
  "summary": {"total": 1234, "matched": 42},
  "symbols": [{"name": "...", "undecorated_name": "...", "rva": "0x1a210",
               "va": "0x18001a210", "size": 128, "kind": "function"}]
}
~~~

编码规则与 [JSON_OUTPUT.md](JSON_OUTPUT.md) 一致:`rva`/`va`/`image_base`/`timestamp`/
`checksum` 为 `0x` 前缀小写十六进制字符串,`size`/`image_size` 为十进制整数,文本严格
UTF-8(非法 UTF-8 报错而不是静默改写)。

### 5.3 csv

首行是选中的字段名,其后每行一个符号;转义规则同 [CSV_OUTPUT.md](CSV_OUTPUT.md)(含
`,`、`"`、`\r`、`\n` 的字段加引号,`"` 双写,行尾 `\r\n`)。`rva`/`va` 以 `0x` 十六进制
字符串写入,`size` 为十进制。

## 6. 模块状态与退出码

| 状态 | 处理 |
|---|---|
| `symbols_loaded` / `exports_only` | 枚举并输出 |
| `no_symbols` | 输出空列表,退出 0 |
| `image_not_found` / `load_failed` 等加载失败 | 报错,退出 1 |
| `unsupported_platform` | 退出 5 |

退出码遵循 [CLI.md](CLI.md) 第 12 节:0 成功(含空结果),1 参数/文件/加载错误,5 平台
不支持。

## 7. 符号搜索路径

`--symbol-path` 与 `--symbol-server` 复用 `[symbols]` 段的规则:两者都未配置时回退到
`_NT_SYMBOL_PATH` / `_NT_ALT_SYMBOL_PATH` 环境变量;配置任一者则忽略环境变量。
`--symbol-server` 的值带 `srv*` 前缀(大小写不敏感)时原样透传,否则自动补前缀。详见
[SYMBOLIZATION.md](SYMBOLIZATION.md)。

## 8. 示例

列出 DLL 的全部符号:

~~~powershell
noleax symbols app.dll
~~~

按名字筛选并只看函数:

~~~powershell
noleax symbols --name "*alloc*" --kind function app.dll
~~~

导出机器可读结果:

~~~powershell
noleax symbols --format json --output symbols.json app.dll
noleax symbols --format csv --fields name,rva,kind --output symbols.csv app.dll
~~~
