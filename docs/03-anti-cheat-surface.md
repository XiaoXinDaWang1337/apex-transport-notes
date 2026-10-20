# 03 · 反作弊对观测手段的限制

本文记录在受保护的游戏进程上，**操作系统层面的观测手段还剩哪些**。
结论来自实测，不是推断。

## ETW 被封锁

事件追踪（ETW）是 Windows 上做内核级抓包的基础（`pktmon`、`netsh trace`、
`wpr` 都基于它）。

实测：

```
游戏启动前   pktmon start                 → 成功
游戏运行中   pktmon stop                  → 拒绝访问
             SYSTEM 计划任务执行 stop      → 拒绝访问
             netsh trace start            → error=5
关闭游戏后   pktmon stop                  → 立刻成功，日志正常落盘
```

**连 SYSTEM 都停不掉一个自己开的 ETW 会话。** 这不是权限配置问题，
是反作弊在保护 ETW 会话控制。

推论：任何依赖 ETW 的抓包手段，必须在游戏进程之外的机器上执行。

## 进程权限被精确剥离

对一个正在运行的对局进程逐项测试：

| 请求的权限 | 结果 |
|---|---|
| `PROCESS_QUERY_INFORMATION` | ✅ 可用（`VirtualQueryEx` 正常返回区域信息） |
| `PROCESS_VM_READ` | ❌ `ReadProcessMemory` 返回 `ERROR_INVALID_PARAMETER` |
| `PROCESS_SET_QUOTA` | ❌ `EmptyWorkingSet` 返回 `ERROR_ACCESS_DENIED` |
| `PROCESS_SUSPEND_RESUME` | ❌ `NtSuspendProcess` 返回 `STATUS_ACCESS_DENIED` |
| 模块枚举（`MainModule`） | ❌ 抛异常 |
| `MiniDumpWriteDump` | ❌ `E_INVALIDARG`（缺 VM_READ 的典型返回） |

**`OpenProcess` 本身是成功的**，甚至请求 `PROCESS_ALL_ACCESS` 也返回句柄。
被剥离的是句柄上的具体权限。

这一点很重要：任何"OpenProcess 失败才算被拦"的判断都会得出错误结论——
句柄存在、内存布局可查、字节读不到、进程动不了。

## 这对取证意味着什么

在**不加载驱动、不接硬件**的前提下，从这个进程里取出任何字节都做不到。
剩下的只有：

- 它自己写到磁盘上的文件（没有）
- 它留下的崩溃转储（需要它先崩溃）
- 系统级页面文件里的残留（需要页面被换出）

三条都已实测，见 `04`。

## 附：明文遥测不受影响

值得注意的是，客户端会向遥测端点发明文 statsd 数据包。
那是它自己的出站流量，与进程保护无关。见 `06`。
