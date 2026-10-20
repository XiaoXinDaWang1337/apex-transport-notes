# 01 · 对局 UDP 包格式

## 结论

```
datagram = nonce(12) || ciphertext(n) || tag(16)
总长 = n + 28
```

- `nonce`：每包独立生成的真随机值，随包发送
- `tag`：128 位，AEAD 认证标签
- 密文长度 = 明文长度

## 怎么推出来的

### 第一步：抓包里数长度

对全部 116,747 个对局 UDP 包统计：

```
最小包长      41
长度 < 28     0 个
长度 < 38     0 个
包长 - 28     13 ~ 1200
```

没有任何包短到装不下 28 字节开销，且最小明文长度 13 字节
刚好是一个最小网络通道头的量级。**这暗示固定开销为 28。**

### 第二步：在二进制里验证

发送路径上，加密调用之后紧跟着一句长度调整：

```
NET_SendDatagram:
    call  encrypt_wrapper
    add   ebx, 0x1c          ; +28
```

### 第三步：看加密包装做了什么

```
encrypt_wrapper(ctx, plain, len, out, nonce_buf):
    mov   edx, 0xc                        ; 12
    call  Plat_GenerateRandom             ; 填充 12 字节 nonce
    call  memcpy(out, plain, len)         ; 先把明文拷进输出缓冲区
    ...
    call  aead_core                       ; 原地加密
    ; 返回值 = len + 取整开销
```

`Plat_GenerateRandom` 的实现：

```
BCryptOpenAlgorithmProvider(BCRYPT_RNG_ALGORITHM)
BCryptGenRandom(handle, buf, 12, 0)
```

⇒ **nonce 是每包真随机，不是计数器，也不在会话里推算。**

### 第四步：确认

12（nonce）+ 16（tag）= 28，与统计完全吻合。

## 为什么这重要

### 1. 普通旁听无法解出结构

如果 nonce 是按包序递增的计数器，那么丢失的包可以从相邻包推出 nonce，
某些场景下还能做密钥流分析。**随机 nonce 让这条路不存在。**

### 2. 长度泄露是唯一免费的信号

密文长度 = 明文长度。这是 AEAD 无法隐藏的元数据，
也是"纯元数据雷达"唯一能利用的东西（见 `04`）。

### 3. 判据从统计变成密码学

一旦拿到候选密钥，用 tag 校验即可判真伪，没有假阳性。
见 `tools/aead_oracle.py`。

## 复现所需

- 抓包：任意网关侧抓包（pktmon / tcpdump）
- 静态：目标二进制 + 任意 x86-64 反汇编器

本文所有地址与偏移均与具体版本绑定，换版本需要重新定位。
