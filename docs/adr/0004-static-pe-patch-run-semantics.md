# ADR 0004：static-pe-patch 的运行时使用语义

> 状态：已确认（实现基线）
> 日期：2026-07-31
> 关联：DEVELOPMENT_PLAN.md §15.1、§15.7，P7C

## 背景

开发计划 §15.1 的兼容矩阵把 `static-pe-patch` 只标在 `patch` 操作上，对 `run` 标记“不适用”，
但没有定义打过补丁的可执行文件如何被捕获。如果不给 `run` 一条路径，静态 patch 产物将无法与
控制器/agent IPC 体系协同，P7C 会变成一个无法使用的特性。

## 决策

1. `noleax patch --input X --output Y` 生成自插装副本 Y：新增 `.nlxboot` section，内含
   bootstrap stub、清零的 `BootstrapParameters` 区、agent 文件名、导出哈希与版本标记。
2. 直接运行 Y（资源管理器、任务计划、其他启动器）时参数区为零，stub 立即跳回原入口点，
   程序行为与未打补丁一致，不产生任何捕获。
3. `noleax run --inject-method static-pe-patch -- Y [args]` 是唯一受支持的捕获入口：控制器
   先解析 Y 校验其确为 noleax patch 产物（section、marker、入口点），再以 suspended 方式
   创建进程，把本次会话的 `BootstrapParameters`（pipe 名、session token、超时）写入 Y 的
   内存映像参数区，然后恢复主线程。stub 完成 `LoadLibrary(agent_name)` + bootstrap + ready
   轮询后跳回原入口点。
4. 参数只写入目标进程内存（写时复制的私有页），不修改磁盘上的 Y；同一 Y 可被任意次
   `run` 复用，每次会话参数独立。
5. `agent_name` 只是文件名（默认 `noleax-agent.dll`），由标准 DLL 搜索顺序解析；部署要求是
   agent DLL 与 Y 同目录。文档与 CLI help 必须明确这一点。
6. 未打补丁的目标配合 `--inject-method static-pe-patch` 使用在创建进程前报错（退出码 1）。
   `attach` 不支持该方法（配置校验拒绝）。

## 备选方案（未采纳）

- 环境变量传参：patched stub 解析 `NOLEAX_*` 环境变量。拒绝原因：stub 需要额外解析逻辑与
  环境块扫描，失败模式更难诊断；进程内存写参数已经是现成的成熟通道。
- 让 patched 副本脱离控制器自写 trace：agent 架构以控制器握手为中心，改造成本与风险远超
  V1 收益。

## 后果

- 计划 §15.1 的矩阵按“run 不负责打补丁；patched 副本经 run + static-pe-patch 捕获”解读，
  公开行为以本 ADR 为准，CLI.md/CONFIG.md 已同步。
- patched 副本的文件哈希与签名改变；`patch` 默认拒绝签名文件，`--allow-break-signature`
  时剥离签名 overlay。
