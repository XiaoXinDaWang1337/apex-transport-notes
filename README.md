# Apex Legends: Transport Protection and the Limits of Passive Observation

一个关于 **Apex Legends 客户端传输层保护机制**的逆向研究记录，
以及"一个局域网网关能从中观察到什么、不能观察到什么"的实测边界。

> 结论先行：**网关旁路无法取得对局数据。** 不是"没试成"，而是把整条链走通后，
> 终点是一把在认证 TLS 内下发的每局密钥。七条路径全部实测关闭，证据在本仓库里。

---

## 这个仓库为什么存在

网上关于游戏网络协议的内容，绝大多数是"我做到了"，几乎没有人写
"我证明了做不到，以及卡在哪一环"。后者对后来者更有价值——它能省掉几个月。

同时，这份记录里包含三次**典型的推理错误**（见 `docs/05`），
它们在逆向工程里极其常见，值得单独拿出来当案例。

---

## 核心发现

### 1. 对局 UDP 包格式

```
[12 bytes random nonce][ciphertext N][16 bytes tag]      总长 = N + 28
```

- 加密后长度固定 +0x1C（28 字节）
- nonce 由 `BCryptGenRandom` 每包现场生成，不是计数器
- AEAD 类算法

推导过程见 `docs/01-packet-format.md`。

### 2. 密钥来源

对称密钥**不是**在对局通道内协商出来的，而是在建立连接时"下发"给客户端的：

- 路径 A：DTLS 握手 → HKDF → 装入 16 字节密钥
- 路径 B：连接信息结构体里的字符串字段 → 直接装入

两条路径都在连接建立阶段，且密钥会周期性轮换
（明文遥测里能看到 `new_key` 事件）。

推导过程见 `docs/02-key-delivery.md`。

### 3. 为什么网关拿不到

客户端对后端使用 TLS 1.2，并且**证书校验使用内置固定信任列表**，
不是操作系统证书库：

- 自带三张根证书：DigiCert Global Root G2 / GlobalSign Root CA / Amazon Root CA 1
- 实测：把测试根证书装进 `LocalMachine\Root`，递一张完全合规的叶子证书
  （EKU serverAuth、SAN、完整链），客户端仍然在 ClientHello 之后直接断开
- 加 `-insecure` 启动参数，行为不变

见 `docs/03-anti-cheat-surface.md` 与 `docs/04-negative-results.md`。

---

## 这个仓库**没有**什么

- 没有对局数据
- 没有雷达 / 透视 / 自瞄
- 没有抓包文件（含账号与内网信息，未收录）
- 没有游戏二进制或任何厂商代码
- 没有"如何绕过反作弊"的操作步骤

它是一份**防守视角的记录**：保护是怎么做的、旁路观测的边界在哪。

---

## 目录

```
docs/
  01-packet-format.md        包格式怎么从二进制里推出来
  02-key-delivery.md         密钥从哪里来
  03-anti-cheat-surface.md   反作弊对观测手段的限制（ETW / 进程权限）
  04-negative-results.md     七条路径的实测关闭记录
  05-methodology-postmortem.md  三次证据跳跃的复盘 ← 最有价值的一篇
  06-plaintext-telemetry.md  明文遥测里的会话时序

tools/
  pe_tools.py          PE 导入表解析（含序号导入）、IAT 交叉引用、特征码扫描
  disasm_range.py      区间反汇编，自动标注 rip 相对引用指向的字符串
  ntfs_extents.py      绕过文件锁，从原始卷读取被占用的文件（pagefile/dump）
  aead_oracle.py       用 AEAD tag 作为候选密钥的判定器（128 位，零假阳性）
  tls_pinning_probe.py 判定客户端使用系统证书库还是固定信任列表
  pcapng_flows.py      pcapng 流统计与 TLS SNI 提取
```

---

## 工具的几个要点

### `pe_tools.py` —— 序号导入

Windows 的 `ws2_32.lib` 把 `send` / `sendto` / `socket` 这类核心函数
**按序号**导出，MSVC 链接后导入表里只有序号。

只按名字扫导入表的工具会得出"这个程序没有发包能力"的错误结论。
本工具会把序号反解成函数名（对照系统 DLL 的导出表）。

这是 `docs/05` 里第一个案例的直接来源。

### `aead_oracle.py` —— 128 位判据

```
非 AEAD：错密钥可能解出"看起来像明文"的东西，需要统计判断
AEAD   ：tag 校验，错密钥必然失败
```

所以候选密钥的验证不需要熵、不需要统计、不需要人工看——
一次解密就能定真伪。工具支持在任意大文件里搜 base64 形态的密钥，
并对每 16 字节窗口做穷举。

### `ntfs_extents.py` —— 绕过文件锁

`pagefile.sys`、`hiberfil.sys`、`MEMORY.DMP` 都被内核锁住，无法正常打开。
但 NTFS 的 `$DATA` 属性里的 runlist 记录了物理簇位置，
而原始卷 `\\.\C:` 是可以以管理员身份读取的。

本工具解析 MFT、找到目标文件的 runlist、直接读那些簇。
支持多段碎片文件，分块读取。

---

## 许可

- 代码：MIT
- 文档：CC BY 4.0

## 免责

本仓库用于协议研究与反作弊工程参考。
不包含任何可用于获取不公平游戏优势的实现。
