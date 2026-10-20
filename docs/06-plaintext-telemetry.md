# 06 · 明文遥测里的会话时序

## 现象

客户端会向一个 statsd 端点（UDP 8125）发明文指标。这类流量与加密的对局通道
完全独立，任何网关侧旁听都能直接读到。

## 观察到的事件序列

对同一局游戏，遥测里出现了完整的连接生命周期：

```
client_startdediconnect
dtls.stats_highres.success.<platform>.session      ; 会话建立
client_dediconnected
...
dtls.stats_highres.success.<platform>.new_key      ; 密钥轮换
dtls.stats_highres.success.<platform>.session
...
```

时间线（相对连接时刻）：

```
+0.4s    session
+84s     new_key + session
+132s    new_key + session
+738s    new_key + session
```

其他可读到的事件还包括：

```
miles.stats_highres.language.<lang>.<platform>     ; 音频/本地化子系统
patch.client.stats_highres.stageusage.<platform>   ; 资源加载阶段
pin.client.stats_highres.falloff.<build_id>.<point> ; 启动阶段打点
pin.client.stats_highres.scount.<page>             ; 页面访问计数
```

## 这泄漏了什么

| 信息 | 价值 |
|---|---|
| 何时连上对局服务器 | 高 —— 可用来对齐抓包与内存快照 |
| 何时轮换密钥 | 高 —— 密钥生命周期边界 |
| 构建版本与平台 | 中 |
| 语言与资源状态 | 低 |

**不泄漏**：密钥本身、对局数据、玩家信息。

## 为什么值得记录

### 1. 它把"黑盒"变成了"有时序的黑盒"

即使拿不到内容，也能精确知道"现在是不是在一次会话中"、
"上一次换钥是什么时候"。

### 2. 它验证了 `02` 的结论

遥测里的 `dtls` 与 `new_key` 事件，与二进制里定位到的
`install_key` / `rekey` 路径完全对应。
两条独立证据（静态 + 网络）互相印证。

### 3. 它是干净的旁听面

遥测是客户端主动发出的出站流量，不受进程保护机制约束。
在受保护进程上一切"接入"手段都被关闭之后，这仍然可用。

## 边界

这条信息不足以支撑"雷达"之类的应用——它没有任何位置信息。
它只能回答"会话是否在进行中"。

如果要做纯粹的元数据分析，这是唯一合法的输入源。
