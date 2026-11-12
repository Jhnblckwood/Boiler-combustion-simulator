// ---------------------------------------------------------------------------
//  L5XCrypto  —  Rockwell L5X  EncryptionConfig = 9  demo (encrypt / decrypt)
// ---------------------------------------------------------------------------
//
//  这是一个演示程序，按照所提供指南实现 EncryptionConfig = 9 的结构：
//    - 盐值 + 固定 keymatl -> SHA256 -> 32B 密钥
//    - AES-256 ECB 单块运算 作为密钥流生成器
//    - XOR 流密码模式（加密 = 解密，同一套对称运算）
//    - 2+1+16+16 头部： [00 09][saltKey][IV][verifyValue][ciphertext]
//
//  This is a self-consistent demo: Encrypt() -> Decrypt() round-trips, and the
//  verifyValue check validates the key. To interoperate with REAL Studio 5000
//  L5X files you must supply the two Rockwell-specific constants that the guide
//  does not give (both clearly marked below):
//      1) KeyMatl  : the fixed 63-byte key material.
//      2) ExpandSalt: how the 1-byte saltKey expands to the 16-byte salt.
//  The keystream/verify chaining is also an interpretation of the guide; adjust
//  BuildKeystream/ComputeVerify if your reverse-engineered details differ.
//
//  Build & run:  dotnet run --project L5XCrypto
//  CLI:
//     l5xcrypto demo                      run all three demos (default)
//     l5xcrypto encrypt "<text>"          encrypt text  -> base64 blob
//     l5xcrypto decrypt "<base64>"        decrypt a base64 blob -> text
//     l5xcrypto decryptfile <file.L5X>    decrypt every EncryptionConfig=9 block
// ---------------------------------------------------------------------------

using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;

namespace L5XCrypto;

/// <summary>
/// EncryptionConfig = 9 cipher.
/// Encryption and decryption are the SAME operation (XOR stream cipher).
/// </summary>
public static class L5xCipher
{
    // ----- 头部布局 / header layout (offsets, lengths) ---------------------
    public const int PadLen     = 2;   // 0..1  : 固定 0x00 0x?9
    public const int SaltKeyLen = 1;   // 2     : saltKey (0x01-0xFF, 随机)
    public const int IvLen      = 16;  // 3..18 : 随机 IV
    public const int VerifyLen  = 16;  // 19..34: verifyValue 校验值
    public const int HeaderLen  = PadLen + SaltKeyLen + IvLen + VerifyLen; // 35
    public const byte Pad0 = 0x00;
    public const byte Pad1 = 0x09;     // 低半字节固定为 9

    // ======================================================================
    //  (1) 需要替换为真实罗克韦尔常量 / REPLACE WITH REAL ROCKWELL CONSTANTS
    // ======================================================================

    /// <summary>
    /// 固定 keymatl：63 字节 (0x3F)。此处为占位值，真实 L5X 需替换为真正的 keymatl。
    /// Fixed 63-byte key material — PLACEHOLDER. Replace to match real files.
    /// </summary>
    private static readonly byte[] KeyMatl = BuildPlaceholderKeyMatl();

    /// <summary>
    /// saltKey(1B) -> 16B 盐值。此处假设：将 saltKey 复制 16 次。
    /// Expand the 1-byte saltKey to the 16-byte salt — ASSUMPTION. Adjust as needed.
    /// </summary>
    private static byte[] ExpandSalt(byte saltKey)
    {
        var salt = new byte[16];
        for (int i = 0; i < 16; i++) salt[i] = saltKey;
        return salt;
    }

    private static byte[] BuildPlaceholderKeyMatl()
    {
        var m = new byte[0x3F]; // 63
        for (int i = 0; i < m.Length; i++) m[i] = (byte)((i * 7 + 0x11) & 0xFF);
        return m;
    }

    // ======================================================================
    //  密钥派生 / key derivation
    // ======================================================================

    /// <summary>
    /// saltKey -> 扩展 16B 盐 + 63B 固定 keymatl (共 79B) -> SHA256 -> 32B 密钥。
    /// </summary>
    public static byte[] DeriveKey(byte saltKey)
    {
        byte[] salt = ExpandSalt(saltKey);               // 16B
        var material = new byte[salt.Length + KeyMatl.Length]; // 16 + 63 = 79
        Buffer.BlockCopy(salt, 0, material, 0, salt.Length);
        Buffer.BlockCopy(KeyMatl, 0, material, salt.Length, KeyMatl.Length);
        return SHA256.HashData(material);                // 32B
    }

    // ======================================================================
    //  AES-256 ECB 单块变换 / single-block primitive  E(x)
    //  （密钥扩展: 32B 密钥 -> 240B 轮密钥, 由 AES 实现内部完成）
    // ======================================================================

    private static byte[] AesEcbBlock(byte[] key, byte[] block16)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;   // 纯单块，不加填充
        using var enc = aes.CreateEncryptor();
        return enc.TransformFinalBlock(block16, 0, 16);
    }

    // ======================================================================
    //  (2) 密钥流 + 校验 / keystream + verify  (指南块处理的一种实现)
    // ======================================================================

    /// <summary>
    /// 生成 length 字节的密钥流，并输出 ivFlags / blockOutByte 供校验使用。
    ///   ivFlags     = E(16字节空值)
    ///   初始计数块   = IV xor ivFlags
    ///   blockOutByte = E(初始计数块)           (= 密钥流第一块)
    ///   后续块       = E(计数块++)              (计数器大端 +1)
    /// </summary>
    private static byte[] BuildKeystream(byte[] key, byte[] iv, int length,
                                         out byte[] ivFlags, out byte[] blockOutByte)
    {
        ivFlags = AesEcbBlock(key, new byte[16]);        // E(0)
        var counter = Xor(iv, ivFlags);                  // 初始计数块
        blockOutByte = AesEcbBlock(key, counter);        // 第一块密钥流

        var outBuf = new byte[length];
        int produced = 0;
        var ctr = (byte[])counter.Clone();
        while (produced < length)
        {
            byte[] ks = AesEcbBlock(key, ctr);
            int n = Math.Min(16, length - produced);
            Buffer.BlockCopy(ks, 0, outBuf, produced, n);
            produced += n;
            IncrementCounter(ctr);
        }
        return outBuf;
    }

    /// <summary>verifyValue = ivFlags xor blockOutByte （与明文无关，用于校验密钥/盐是否正确）。</summary>
    private static byte[] ComputeVerify(byte[] ivFlags, byte[] blockOutByte)
        => Xor(ivFlags, blockOutByte);

    // ======================================================================
    //  加密 / encrypt
    // ======================================================================

    public static byte[] Encrypt(byte[] plaintext, byte? saltKey = null, byte[]? iv = null)
    {
        byte sk = saltKey ?? NonZeroRandomByte();        // 0x01-0xFF
        byte[] theIv = iv ?? RandomBytes(16);
        byte[] key = DeriveKey(sk);

        byte[] ks = BuildKeystream(key, theIv, plaintext.Length, out var ivFlags, out var blockOut);
        byte[] cipher = Xor(plaintext, ks);
        byte[] verify = ComputeVerify(ivFlags, blockOut);

        var blob = new byte[HeaderLen + cipher.Length];
        blob[0] = Pad0;
        blob[1] = Pad1;
        blob[2] = sk;
        Buffer.BlockCopy(theIv,  0, blob, 3,  IvLen);
        Buffer.BlockCopy(verify, 0, blob, 19, VerifyLen);
        Buffer.BlockCopy(cipher, 0, blob, HeaderLen, cipher.Length);
        return blob;
    }

    // ======================================================================
    //  解密 / decrypt
    // ======================================================================

    public static byte[] Decrypt(byte[] blob)
    {
        if (blob.Length < HeaderLen)
            throw new ArgumentException($"数据太短：至少需要 {HeaderLen} 字节头部，实际 {blob.Length}。");
        if (blob[0] != Pad0 || (blob[1] & 0x0F) != Pad1)
            throw new ArgumentException($"头部填充不符：期望 00 ?9，实际 {blob[0]:X2} {blob[1]:X2}。");

        byte sk = blob[2];
        byte[] iv     = blob[3..19];
        byte[] verify = blob[19..35];
        byte[] cipher = blob[35..];

        byte[] key = DeriveKey(sk);
        byte[] ks = BuildKeystream(key, iv, cipher.Length, out var ivFlags, out var blockOut);

        byte[] expect = ComputeVerify(ivFlags, blockOut);
        if (!CryptographicOperations.FixedTimeEquals(expect, verify))
            throw new CryptographicException(
                "校验失败：verifyValue 不匹配（密钥/盐/keymatl 不正确，或该块并非本算法所加密）。");

        return Xor(cipher, ks);   // XOR 流密码：与加密同一套运算
    }

    // ---- 便捷 base64 封装 / base64 helpers -------------------------------
    public static string EncryptTextToBase64(string plaintext)
        => Convert.ToBase64String(Encrypt(Encoding.UTF8.GetBytes(plaintext)));

    public static string DecryptBase64ToText(string base64)
        => Encoding.UTF8.GetString(Decrypt(Convert.FromBase64String(StripWhitespace(base64))));

    // ---- 工具 / utilities ------------------------------------------------
    private static byte[] Xor(byte[] a, byte[] b)
    {
        int n = Math.Min(a.Length, b.Length);
        var r = new byte[n];
        for (int i = 0; i < n; i++) r[i] = (byte)(a[i] ^ b[i]);
        return r;
    }

    private static void IncrementCounter(byte[] ctr)
    {
        for (int i = ctr.Length - 1; i >= 0; i--)
            if (++ctr[i] != 0) break;   // 大端 +1，带进位
    }

    private static byte NonZeroRandomByte()
    {
        Span<byte> b = stackalloc byte[1];
        do { RandomNumberGenerator.Fill(b); } while (b[0] == 0);
        return b[0];
    }

    private static byte[] RandomBytes(int n)
    {
        var b = new byte[n];
        RandomNumberGenerator.Fill(b);
        return b;
    }

    public static string StripWhitespace(string s)
    {
        var sb = new StringBuilder(s.Length);
        foreach (char c in s)
            if (!char.IsWhiteSpace(c)) sb.Append(c);
        return sb.ToString();
    }

    public static string ToHex(byte[] b) => Convert.ToHexString(b);
}

/// <summary>命令行入口 + 三个演示。</summary>
public static class Program
{
    public static int Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;
        try
        {
            string cmd = args.Length > 0 ? args[0].ToLowerInvariant() : "demo";
            switch (cmd)
            {
                case "demo":        RunAllDemos(); break;
                case "encrypt":     CmdEncrypt(Arg(args, 1)); break;
                case "decrypt":     CmdDecrypt(Arg(args, 1)); break;
                case "decryptfile": CmdDecryptFile(Arg(args, 1)); break;
                default:
                    Console.Error.WriteLine($"未知命令: {cmd}");
                    Console.Error.WriteLine("用法: demo | encrypt <text> | decrypt <base64> | decryptfile <path>");
                    return 2;
            }
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("错误: " + ex.Message);
            return 1;
        }
    }

    private static string Arg(string[] a, int i)
        => i < a.Length ? a[i] : throw new ArgumentException("缺少参数。");

    private static void RunAllDemos()
    {
        Hr("L5X EncryptionConfig = 9  演示 (demo)");
        Console.WriteLine("注意: keymatl / 盐扩展为占位值；真实 L5X 文件需替换为罗克韦尔真实常量。\n");

        Demo1_DecryptEncodedData();
        Demo2_EncryptText();
        Demo3_DecryptWholeFile();
    }

    // -------- 演示 1：单独解密 <EncodedData> 下的 base64 密文 --------------
    private static void Demo1_DecryptEncodedData()
    {
        Hr("演示 1 — 解密 <EncodedData EncryptionConfig=\"9\"> 的 base64 密文");

        // 为演示先生成一段密文（固定 salt/IV 以便结果可复现）。
        string routine = "<RLLContent><Rung Number=\"0\"><Text>XIC(Start)OTE(Motor);</Text></Rung></RLLContent>";
        byte[] blob = L5xCipher.Encrypt(Encoding.UTF8.GetBytes(routine),
                                        saltKey: 0xA7, iv: Enumerable.Range(0, 16).Select(i => (byte)i).ToArray());
        string base64 = Convert.ToBase64String(blob);

        Console.WriteLine("EncodedData base64 (saltKey=0xA7):");
        Console.WriteLine("  " + base64);
        Console.WriteLine($"  头部: pad={blob[0]:X2}{blob[1]:X2}  saltKey={blob[2]:X2}  " +
                          $"IV={L5xCipher.ToHex(blob[3..19])}");
        Console.WriteLine($"  verifyValue={L5xCipher.ToHex(blob[19..35])}");

        string text = L5xCipher.DecryptBase64ToText(base64);
        Console.WriteLine("\n解密结果:");
        Console.WriteLine("  " + text);
        Console.WriteLine();
    }

    // -------- 演示 2：单独对文本加密 -------------------------------------
    private static void Demo2_EncryptText()
    {
        Hr("演示 2 — 对文本加密 (并验证可解回)");

        string plain = "Hello Rockwell L5X — 这是一段要加密的例程文本。";
        string base64 = L5xCipher.EncryptTextToBase64(plain);
        string back   = L5xCipher.DecryptBase64ToText(base64);

        Console.WriteLine("明文    : " + plain);
        Console.WriteLine("密文(b64): " + base64);
        Console.WriteLine("解回明文: " + back);
        Console.WriteLine("往返一致: " + (back == plain));

        // 演示随机性：再加密一次 -> base64 不同，但都能解回（每次导出都变换）。
        string base64b = L5xCipher.EncryptTextToBase64(plain);
        Console.WriteLine("再次加密: " + base64b);
        Console.WriteLine($"两次密文不同(随机 salt/IV): {base64b != base64}；均可解回: " +
                          (L5xCipher.DecryptBase64ToText(base64b) == plain));
        Console.WriteLine();
    }

    // -------- 演示 3：对完整 L5X 文件进行解密 ----------------------------
    private static void Demo3_DecryptWholeFile()
    {
        Hr("演示 3 — 解密完整 L5X 文件中所有 EncryptionConfig=\"9\" 的 EncodedData");

        string xml = BuildSampleL5X();
        string path = Path.Combine(Path.GetTempPath(), "L5XCrypto_sample.L5X");
        File.WriteAllText(path, xml, new UTF8Encoding(false));
        Console.WriteLine("已写出示例文件: " + path + "\n");

        DecryptFile(path);
        Console.WriteLine();
    }

    // -------- CLI 命令 ---------------------------------------------------
    private static void CmdEncrypt(string text)
        => Console.WriteLine(L5xCipher.EncryptTextToBase64(text));

    private static void CmdDecrypt(string base64)
        => Console.WriteLine(L5xCipher.DecryptBase64ToText(base64));

    private static void CmdDecryptFile(string path) => DecryptFile(path);

    /// <summary>
    /// 解析 L5X (XML)，找出所有 EncryptionConfig="9" 的 &lt;EncodedData&gt;，逐个解密。
    /// </summary>
    private static void DecryptFile(string path)
    {
        var doc = XDocument.Load(path);
        var nodes = doc.Descendants("EncodedData")
                       .Where(e => (string?)e.Attribute("EncryptionConfig") == "9")
                       .ToList();

        if (nodes.Count == 0)
        {
            Console.WriteLine("未找到 EncryptionConfig=\"9\" 的 EncodedData 节点。");
            return;
        }

        int idx = 0;
        foreach (var node in nodes)
        {
            idx++;
            string name = (string?)node.Attribute("Name") ?? "(未命名)";
            string type = (string?)node.Attribute("Type") ?? "?";
            string encType = (string?)node.Attribute("EncodedType") ?? "?";
            string base64 = L5xCipher.StripWhitespace(node.Value);

            Console.WriteLine($"[{idx}] EncodedData  Name={name}  EncodedType={encType}  Type={type}");
            try
            {
                string text = L5xCipher.DecryptBase64ToText(base64);
                Console.WriteLine("     解密成功，长度 " + text.Length + " 字符:");
                foreach (var line in text.Split('\n'))
                    Console.WriteLine("       " + line.TrimEnd('\r'));
            }
            catch (Exception ex)
            {
                Console.WriteLine("     解密失败: " + ex.Message);
            }
        }
    }

    // 构造一个示例 L5X（其中密文由本算法加密），用于演示完整文件解密。
    private static string BuildSampleL5X()
    {
        string main  = "<RLLContent><Rung Number=\"0\"><Text>XIC(Start)XIO(Stop)OTE(Run);</Text></Rung></RLLContent>";
        string fault = "<RLLContent><Rung Number=\"0\"><Text>XIC(Fault)OTL(Alarm);</Text></Rung></RLLContent>";
        string b64Main  = L5xCipher.EncryptTextToBase64(main);
        string b64Fault = L5xCipher.EncryptTextToBase64(fault);

        return $"""
        <?xml version="1.0" encoding="UTF-8"?>
        <RSLogix5000Content SchemaRevision="1.0" TargetName="Demo">
          <Controller Name="Demo">
            <Programs>
              <Program Name="MainProgram">
                <Routines>
                  <Routine Name="MainRoutine" Type="RLL">
                    <EncodedData EncodedType="Routine" Name="MainRoutine" Type="RLL" EncryptionConfig="9">{b64Main}</EncodedData>
                  </Routine>
                  <Routine Name="FaultRoutine" Type="RLL">
                    <EncodedData EncodedType="Routine" Name="FaultRoutine" Type="RLL" EncryptionConfig="9">{b64Fault}</EncodedData>
                  </Routine>
                </Routines>
              </Program>
            </Programs>
          </Controller>
        </RSLogix5000Content>
        """;
    }

    private static void Hr(string title)
    {
        Console.WriteLine(new string('=', 72));
        Console.WriteLine(title);
        Console.WriteLine(new string('=', 72));
    }
}
