# Noleax Windows x64 打包

> 状态：P8.6 release-candidate packaging gate

V1 使用 CMake install 与 CPack ZIP 生成自包含目录。包只用于 RC 验证；Noleax 自身许可证、安全联系
方式和签名策略确定之前，不得公开分发。

## 生成本地包

在仓库根目录运行：

~~~powershell
. .\scripts\Enter-NoleaxDevShell.ps1
cmake --preset windows-x64-release
cmake --build --preset windows-x64-release
cpack --config .\build\windows-x64-release\CPackConfig.cmake -G ZIP
~~~

默认输出位于 `build/windows-x64-release/package/`：

- `noleax-0.1.0-windows-x64.zip`
- `noleax-0.1.0-windows-x64.zip.sha256`

这些是本地生成物，不加入 Git，也不代表获准发布。

## 包布局

~~~text
noleax-0.1.0-windows-x64/
  bin/
    noleax.exe
    noleax-agent.dll
  docs/
  examples/
  licenses/
  README.md
  BUILDING.md
  SECURITY.md
  THIRD_PARTY_NOTICES.md
~~~

controller 和 agent 必须保持在同一个 `bin` 目录。Hoox、LZ4、Zstandard 与 MSVC runtime 静态链接；
CLI11 与 toml++ 由头文件编译。`licenses/` 保存锁定 vcpkg baseline 的六份原始版权文本。两个 PE 的
动态依赖必须全部由受支持 Windows 提供，包不携带第三方 DLL。

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

这证明包不依赖构建树中的 Noleax DLL；测试 workload 仍由测试构建提供。最终 clean-machine/VM 的人工
验收属于 P8.7，并应在未安装 Visual Studio 的 Windows x64 环境中执行。
