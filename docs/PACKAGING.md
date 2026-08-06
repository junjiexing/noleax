# Noleax Windows x64 打包


V1 使用 CMake install 与 CPack ZIP 生成自包含目录。Noleax 以 MIT License 发布。

## 生成本地包

在仓库根目录运行：

~~~powershell
. .\scripts\Enter-NoleaxDevShell.ps1
cmake --preset windows-x64-release
cmake --build --preset windows-x64-release
cpack --config .\build\windows-x64-release\CPackConfig.cmake -G ZIP
~~~

默认输出位于 `build/windows-x64-release/package/`：

- `noleax-0.4.1-windows-x64.zip`
- `noleax-0.4.1-windows-x64.zip.sha256`

这些是本地生成物，不加入 Git，也不代表获准发布。

## 包布局

~~~text
noleax-0.4.1-windows-x64/
  bin/
    noleax.exe
    noleax-agent.dll
  docs/
    quickstart.md
    troubleshooting.md
    cli.md
    config.md
    console-output.md
    json-output.md
    csv-output.md
    trace-format.md
    trace-recovery.md
    symbolization.md
    symbols.md
    static-pe-patch.md
    hook-profiles.md
    custom-hooks.md
    roadmap.md
    schema/
      noleax-analysis-v1.schema.json
      noleax-analysis-v2.schema.json
      noleax-analysis-v3.schema.json
      noleax-analysis-v4.schema.json
      noleax-symbols-v1.schema.json
  examples/
  licenses/
  README.md
  BUILDING.md
  SECURITY.md
  LICENSE
  THIRD_PARTY_NOTICES.md
~~~

controller 和 agent 必须保持在同一个 `bin` 目录。Hoox、LZ4、Zstandard 与 MSVC runtime 静态链接；
CLI11 与 toml++ 由头文件编译。`licenses/` 保存锁定 vcpkg baseline 的六份原始版权文本。两个 PE 的
动态依赖必须全部由受支持 Windows 提供，包不携带第三方 DLL。

`docs/` 只包含使用方法相关的文档（快速上手、排错、命令与配置、输出格式、符号化、trace 格式与
恢复、静态 patch、hook profile、未完成能力），安装时重命名为小写 kebab 名；内部设计文档保留在
仓库中，不随包发布。

## 自动 smoke

~~~powershell
. .\scripts\Enter-NoleaxDevShell.ps1
pwsh -NoProfile -File .\scripts\Test-NoleaxPackage.ps1 -SkipBuild
~~~

脚本在 `_temp` 下创建隔离工作区，并在结束后删除。它会：

1. 执行 `cmake --install` 并检查 staging 布局。
2. 对 exe、agent 和实际引用到的包内 DLL 递归运行 `dumpbin /dependents`。
3. 拒绝任何不位于 Windows system directory 的依赖，并显式拒绝动态 MSVC runtime。
4. 校验六份版权文件的 SHA-256，防止依赖更新时遗漏声明 review。
5. 从 staging 执行 version、doctor、真实 NT Heap capture 和两种 analyze 示例。
6. 生成 ZIP 和 SHA-256 companion，解压到新目录后重复布局、依赖和端到端工作流。

这证明包不依赖构建树中的 Noleax DLL；测试 workload 仍由测试构建提供。发布到干净环境前，应在
未安装 Visual Studio 的 Windows x64 机器上做一次人工验证。

## CI 发布

ci workflow 在 `windows-x64-release` job 的构建与测试全部通过后执行 `cpack -G ZIP`，把
`noleax-0.4.1-windows-x64.zip` 与 `.sha256` 作为 workflow artifact 保留（30 天）。当整个 CI
在以下事件上成功时，`release` job 会把同一对文件上传到 GitHub Releases：

- 推送 `v*` 标签：创建（或更新）该标签对应的 release，ZIP 作为附件。
- 推送 main：更新名为 `ci-latest` 的滚动预发布（prerelease），附件同名替换。

包内含 `bin/`（noleax.exe 与 noleax-agent.dll）、`LICENSE`、第三方声明与 `licenses/` 原始版权
文本，布局与本地 `cpack` 产物一致。
