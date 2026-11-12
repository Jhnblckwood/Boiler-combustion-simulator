# L5XCrypto — Rockwell L5X `EncryptionConfig = 9` demo

A small C# console program implementing the structure of Rockwell's `EncryptionConfig = 9`
routine encryption, and demonstrating the three requested cases.

## 算法结构 / structure

```
base64 解码后:
  偏移 0..1   (2B)  固定填充 0x00 0x?9
  偏移 2      (1B)  saltKey   随机 0x01-0xFF（每次导出都变）
  偏移 3..18  (16B) IV        随机初始向量
  偏移 19..34 (16B) verifyValue 校验值
  偏移 35..   (剩余) ciphertext 密文

密钥派生:  saltKey -> 16B 盐 + 63B 固定 keymatl (79B) -> SHA256 -> 32B 密钥
密钥流:    E(x) = AES-256 ECB 单块；ivFlags=E(0)；块 = E((IV xor ivFlags)++)
流密码:    plaintext xor keystream  (加密 = 解密，对称)
校验:      verifyValue = ivFlags xor blockOutByte
```

## 运行 / run

```bash
dotnet run --project L5XCrypto                     # 三个演示（默认）
dotnet run --project L5XCrypto -- encrypt "text"   # 加密文本 -> base64
dotnet run --project L5XCrypto -- decrypt "<b64>"  # 解密 base64 -> 文本
dotnet run --project L5XCrypto -- decryptfile a.L5X # 解密整个 L5X 文件
```

## ⚠️ 对接真实 L5X 文件 / to decrypt REAL files

本程序**自洽**（Encrypt↔Decrypt 往返正确、verify 校验有效），但指南未给出两个
罗克韦尔专有常量，程序中用占位值代替。要解密真正的 Studio 5000 导出文件，必须在
`L5xCipher` 中替换：

1. `KeyMatl` — 真实的 63 字节固定 keymatl。
2. `ExpandSalt` — saltKey(1B) 展开为 16B 盐值的真实规则。

此外 `BuildKeystream` / `ComputeVerify` 中的块链接方式是对指南的一种实现，若你逆向
得到的细节不同，请据此调整。这些都在 `Program.cs` 中清楚标注。

> 仅用于对**你自己拥有**的程序进行恢复 / 互操作。
