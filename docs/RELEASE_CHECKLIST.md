# Noleax Windows x64 V1 发布检查清单

> 状态：AI 技术门禁完成，等待人工最终验收
>
> 候选分支：`feat/v1-release-candidate`
>
> 自动证据基线：`e819ece06df534170b53c9c6655baa92f37fa839`

本清单将 AI 可自动完成的技术门禁与必须由人工作出的产品、法律和发布决定分开。勾选人工项目并不
自动授权创建 tag 或发布；最终仍需一条明确的发布指令。

## 1. AI 技术门禁

- [x] Debug、Release、Hardened 全量套件通过。
- [x] 37 个 hardened PE 通过 CFG/CET metadata，五个 hook 目标通过 runtime mitigation。
- [x] 五组 quiescence race 各 100/100，native profile 100/100，长 ABI 差分 3/3。
- [x] Application Verifier/Full Page Heap 三轮通过，19 个 IFEO key 全部清理，导出日志零记录。
- [x] 50/50 soak、206/206 不可信 trace corpus 和 15/15 性能 trace 通过。
- [x] Quickstart、TOML 示例、故障排查和各注入方法与 patch 的可执行文档测试通过。
- [x] `/MT` 自包含打包、依赖闭包、第三方版权文本和解压后端到端 package smoke 通过。
- [x] 测试 ZIP 和校验文件已删除；没有创建 tag，也没有发布二进制。

完整数字、二进制哈希和范围见 [RELEASE_CANDIDATE.md](RELEASE_CANDIDATE.md)。

## 2. 人工 clean-machine 验收

### 2.1 在构建机生成临时候选包

确认工作树只有已 review 的候选内容，然后在仓库根目录执行：

~~~powershell
git status --short
git rev-parse HEAD
. .\scripts\Enter-NoleaxDevShell.ps1
cmake --preset windows-x64-release
cmake --build --preset windows-x64-release
ctest --preset windows-x64-release -R "package.windows-x64-smoke" --output-on-failure
cpack --config .\build\windows-x64-release\CPackConfig.cmake -G ZIP
Get-FileHash -Algorithm SHA256 .\build\windows-x64-release\package\noleax-0.1.0-windows-x64.zip
~~~

- [ ] `git status --short` 为空，并记录候选 commit。
- [ ] package smoke 1/1 通过。
- [ ] 记录 ZIP 的文件大小和 SHA-256，并通过可信方式复制 ZIP 与独立记录的哈希到 VM。

### 2.2 在干净 Windows x64 VM 验证

VM 应为受支持的 Windows 10/11 x64，且没有 Visual Studio、vcpkg、Noleax 源码或构建目录。先核对
复制后的 ZIP 哈希，再解压到普通用户可写目录：

~~~powershell
Get-FileHash -Algorithm SHA256 .\noleax-0.1.0-windows-x64.zip
Expand-Archive .\noleax-0.1.0-windows-x64.zip -DestinationPath .\noleax-rc
Set-Location .\noleax-rc\noleax-0.1.0-windows-x64\bin
.\noleax.exe --version
.\noleax.exe doctor
~~~

- [ ] 复制前后的 ZIP SHA-256 完全一致。
- [ ] 包只有一个顶层目录，`bin/noleax.exe` 与 `bin/noleax-agent.dll` 同目录。
- [ ] `--version` 正常退出；`doctor` 的 required checks 全部为 `pass`。
- [ ] 没有出现缺少 MSVC runtime、Hoox、LZ4、Zstd 或其他第三方 DLL 的加载错误。

使用一段已授权、可重复且可安全退出的原生 x64 workload 完成真实捕获；将下面的目标和参数替换为
VM 上的实际程序：

~~~powershell
.\noleax.exe run --hook-profile windows-nt-heap --max-trace-size 256MiB `
  --trace .\run.nlx -- C:\path\to\approved-x64-target.exe --workload sample
.\noleax.exe analyze --mode events --format json --output .\events.json .\run.nlx
.\noleax.exe analyze --mode outstanding --a 0s --b 10s --format csv `
  --output .\outstanding.csv .\run.nlx
~~~

再启动一个长期运行的已授权 x64 目标并执行 attach：

~~~powershell
.\noleax.exe attach --pid <PID> --hook-profile windows-nt-heap `
  --capture-duration 10s --trace .\attach.nlx
.\noleax.exe analyze --mode events --format console .\attach.nlx
~~~

- [ ] run 在目标入口前完成注入，目标行为与未注入基线一致且正常退出。
- [ ] attach 不导致目标 crash/hang，10 秒后 controller 正常停止、drain 并 finalize。
- [ ] events JSON、outstanding CSV 和 console 均可读，调用栈至少保留地址或 module+offset fallback。
- [ ] run trace 报告完整；attach 结果明确报告 preexisting blind spot，退出码 2 被正确理解为不完整而非
  崩溃。
- [ ] trace 未超过配置上限，目标、trace 和分析输出路径均没有覆盖需要保留的数据。

## 3. 人工产品与风险验收

- [ ] 接受默认 LZ4、64 帧和本机参考 1.490x 中位开销；或记录必须解决的性能问题。
- [ ] review console/JSON/CSV 输出、错误信息、Quickstart 与三份 TOML 示例，确认普通用户可独立操作。
- [ ] 接受 V1 仅支持 Windows x64、原生同架构目标，以及 run 四种、attach 两种注入方法与
  static PE patch。
- [ ] 接受自定义符号 hook DSL、trace rotation、unload-on-stop 和多 trace 联合分析延期到 V1 之后。
- [ ] review [SECURITY_AUDIT.md](SECURITY_AUDIT.md) 的残余风险，尤其是 native injection、trace 中的敏感
  元数据和 DbgHelp 解析 trace 指定本地映像。

人工记录：

~~~text
候选 commit：
ZIP SHA-256：
Windows 版本：
验证目标：
run 结果：
attach 结果：
analyze 结果：
性能结论：
验收人/日期：
备注：
~~~

## 4. 公开发布前的必选决策

- [ ] 选择 Noleax 自身许可证，加入许可证文本，并 review 打包结果。
- [ ] 在 `SECURITY.md` 中提供持久、可用的私密安全联系方式或启用平台私密报告功能。
- [ ] 决定官方二进制是否必须 Authenticode 签名，以及证书保管、时间戳和撤销流程。
- [ ] 决定正式版本号、release notes、支持周期与已知问题披露方式。
- [ ] 所有上述改变完成后重新运行受影响的 build/test/package/documentation 门禁。

## 5. 最终授权

- [ ] 人工明确批准 P8.7 技术验收。
- [ ] 人工明确批准合并候选分支。
- [ ] 人工明确批准创建指定名称的 tag。
- [ ] 人工明确批准发布指定哈希的归档。

本次收口停在 P9 前。上述每一项都需要独立、明确的授权；未授权时不得执行对应动作，开始 P9 也需
另行给出明确指令。
