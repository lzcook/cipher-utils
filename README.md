# 加密解密工具类

一个功能完整的Java加密工具库，既支持国际通用的加密算法(RSA, AES等)，也支持国产密码算法(SM2, SM3, SM4)。

## 包含加密算法
* Base32
* Base64
* BinaryCodec
* Hex
* Hmac
* MD5
* SHA
* RSA
* AES
* Blowfish
* DES
* DESede
* RC4
* SM2
* SM3
* SM4

## Maven依赖
```xml
<dependency>
    <groupId>com.github.lzcook</groupId>
    <artifactId>util-cipher</artifactId>
    <version>1.0.0</version>
</dependency>
```

## 快速开始

### 非对称加密
* **RSAUtils** -  国际非对称加密标准
* **SM2Utils** - 国密椭圆曲线公钥密码算法

### 对称加密
* **AESUtils** - 高级加密标准(Advanced Encryption Standard)
* **SM4Utils** - 国密无线局域网标准分组数据算法
* BlowfishUtils
* DESUtils - 美国数据加密标准(Data Encryption Standard)
* DESedeUtils - 三重DES
* RC4Utils

### 散列/摘要/杂凑
* **HmacUtils** - HMAC消息认证码
* **SHAUtils** - SHA系列散列算法
* **SM3Utils** - 国密杂凑算法
* MD5Utils（已弃用）

### 工具类
* **RandomUtil** - 密码学安全的随机数生成器
* KeyEncodedUtils - 密钥编码工具

---

## 📚 算法详解

### 非对称加密

#### RSA
**算法介绍**
- 1978年由Ron Rivest、Adi Shamir和Leonard Adleman三人发明
- 最典型的非对称加密算法
- 支持数字签名和加密解密
- 公钥X509格式，私钥PKCS8格式

**功能特性**
- ✅ 签名、验签
- ✅ 公钥加密、私钥解密
- ✅ 私钥加密、公钥解密
- ✅ 密钥导出导入（支持DER和PEM格式）
- ✅ 密钥文件读写

**安全最佳实践**
- ✅ **推荐使用OAEP填充**：提供概率加密，抗选择密文攻击（CCA），符合现代安全标准
- ⚠️  **避免使用PKCS1填充**：存在已知安全漏洞（如Bleichenbacher攻击），仅用于兼容旧系统
- ❌ **禁止使用NoPadding**：完全不安全，除非实现自定义填充方案
- 🔑 **密钥长度建议**：至少2048位，推荐3072位或4096位

**默认加密方式**
- 默认的 `encrypt/decrypt` 方法使用 **OAEPWithSHA-256AndMGF1Padding**
- 这是符合NIST推荐的现代加密标准，提供最佳的安全性和兼容性平衡

**填充方式对比**

| 填充方式 | 安全性 | 适用场景 | 可加密数据量(2048位密钥) | 说明 |
|---------|--------|----------|----------------------|------|
| **OAEPWithSHA-256** ⭐ | ⭐⭐⭐⭐⭐ | 所有新项目的首选方案 | ~190字节 | 概率加密、抗CCA攻击、SHA-256安全哈希、符合现代标准 |
| **OAEPWithSHA-384/512** | ⭐⭐⭐⭐⭐ | 金融、军事、政府等高安全场景 | ~158/126字节 | 更强的安全性，性能稍低 |
| **OAEPPadding** | ⭐⭐⭐⭐ | 需要兼容旧系统的OAEP实现 | ~214字节 | 默认使用SHA-1（已被淘汰） |
| **PKCS1Padding** | ⭐⭐ | 仅用于兼容旧系统 | ~245字节 | 存在Bleichenbacher攻击风险，已弃用 |

**关于ECB模式说明**
- RSA中的"ECB"不是真正的ECB分块模式，只是Java API的命名约定
- RSA本质上只加密单个数据块，不存在像AES-ECB那样的安全问题
- `RSA/ECB/XXXPadding` 和 `RSA/NONE/XXXPadding` 实际上是等价的

#### SM2
**算法介绍**
- 2010年12月17日由国家密码管理局发布
- 国产椭圆曲线公钥密码算法，替代RSA的国密标准
- 基于椭圆曲线离散对数问题（ECC算法的一种）
- 计算复杂度是指数级，求解难度较大

**技术特点**
- **密钥长度**：256位
- **安全强度**：比RSA 2048位更高
- **运算速度**：快于RSA
- **密钥格式**：公钥X509格式，私钥PKCS8格式
- **密文编码**：采用ASN.1/DER方式编码

**功能特性**
- ✅ 签名、验签
- ✅ 密钥交换
- ✅ 公钥加密、私钥解密
- ✅ 密钥导出导入（支持DER和PEM格式）
- ✅ 密钥文件读写

**优势对比**
- 同等安全程度下，椭圆曲线密码所需密钥长度远小于RSA
- SM2 256位 ≈ RSA 2048位安全强度
- 更高的加密效率和更小的密钥存储空间

---

### 对称加密

#### AES
**算法介绍**
- 高级加密标准(Advanced Encryption Standard)
- 用来替代原先的DES，速度快、安全性高
- 支持128/192/256位密钥长度，块长128位
- 在软件及硬件上都能快速地加解密，且只需要很少的存储器

**功能特性**
- ✅ **便捷加密**：`encrypt(data, key, iv)` 使用推荐的CBC模式，简单易用
- ✅ **GCM模式**（强烈推荐）：认证加密，提供数据完整性和机密性保障
- ✅ **CBC模式**（推荐）：传统块加密模式，平衡性能和安全，需要随机IV
- ✅ **CTR模式**（推荐）：流式加密模式，不需要填充
- ⚠️  **ECB模式**（已弃用）：仅用于兼容旧系统，不安全
- ✅ **密钥和IV生成**：提供密码学安全的随机密钥和IV生成工具

**安全提示**
- **推荐顺序**：GCM > CTR > CBC > CFB/OFB > ECB
- ❌ **禁止使用ECB模式**：相同明文产生相同密文，仅用于兼容旧系统
- ✅ **必须使用随机IV**：每次加密使用不同的IV
- ✅ **GCM模式**：提供认证加密，防止篡改

**跨语言兼容性**
- Java的PKCS5Padding等同于PKCS7Padding（对于16字节块）
- 其他语言通常使用PKCS7Padding命名
- CTR和GCM模式使用NoPadding

**方法命名规范**
- `encrypt(data, key, iv)` / `decrypt(data, key, iv)` - 便捷方法，默认使用推荐的CBC模式
- `encryptGCM` / `decryptGCM` - GCM模式（强烈推荐，最高安全性）
- `encryptCBC` / `decryptCBC` - CBC模式（推荐，平衡性能和安全）
- `encryptCTR` / `decryptCTR` - CTR模式（推荐，流式加密）
- `encryptECB` / `decryptECB` - ECB模式（已弃用，仅用于兼容旧系统）

#### SM4
**算法介绍**
- 2012年3月由国家密码管理局发布
- 无线局域网国密标准的分组数据算法
- 密钥长度128位，块长128位，类似AES
- 中国国家密码标准

**功能特性**
- 与AES类似，支持多种加密模式
- 推荐优先级：GCM > CTR > CBC > ECB
- 所有安全建议和使用方式与AES一致

---

### 散列算法

#### MD5
- ⚠️ **已弃用** - 存在碰撞漏洞，仅用于非安全场景
- 不推荐用于密码存储或数字签名
- 可用于文件完整性校验（非安全场景）

#### SHA系列
**算法介绍**
- Secure Hash Algorithm（安全散列算法）

**推荐使用**
| 算法 | 状态 | 说明 |
|------|------|------|
| SHA-1 | ⚠️ 已弃用 | 存在碰撞漏洞，不应继续使用 |
| SHA-224 | ⚠️ 不推荐 | 虽仍安全，但抗碰撞能力不及SHA-256 |
| **SHA-256** | ✅ 推荐 | 平衡安全性和性能，优先推荐 |
| **SHA-384** | ✅ 推荐 | 高安全场景 |
| **SHA-512** | ✅ 推荐 | 高安全场景 |
| **SHA3-256** | ✅ 推荐 | 新一代标准(JDK9+) |
| **SHA3-384** | ✅ 推荐 | 新一代标准(JDK9+) |
| **SHA3-512** | ✅ 推荐 | 新一代标准(JDK9+) |

**安全建议**
- 优先推荐使用SHA-256及以上长度进行加密摘要
- 新项目建议使用SHA-256或SHA3-256
- 高安全场景推荐SHA-384/SHA-512或SHA3系列

#### HMAC
**算法介绍**
- HMAC（Hash-based Message Authentication Code）
- 基于密钥的散列消息认证码
- 提供数据完整性和身份验证

**推荐使用**
- ✅ HmacSHA256（推荐）
- ✅ HmacSHA384（高安全场景）
- ✅ HmacSHA512（高安全场景）
- ⚠️  HmacMD5（已弃用）
- ⚠️  HmacSHA1（已弃用）

#### SM3
**算法介绍**
- 国产SM3杂凑算法
- 国家密码管理局发布的国密标准
- 输出长度256位，与SHA-256相当

---

### 工具类

#### RandomUtil
**功能介绍**
- 提供密码学安全的随机数生成功能
- 用于生成密钥、IV、盐值等

**技术特点**
- 使用`SecureRandom`提供密码学安全的随机数
- 使用`ThreadLocal`确保线程安全并复用实例
- 支持生成随机字节、字符串(Base64)、十六进制等

**主要方法**
- `generateRandomBytes(int length)` - 生成随机字节数组
- `generateRandomString(int length)` - 生成Base64编码的随机字符串
- `generateRandomHex(int byteLength)` - 生成十六进制随机字符串
- `generateRandomInt(int bound)` - 生成随机整数
- `generateRandomIntInRange(int min, int max)` - 生成指定范围的随机整数

---

## 🔐 安全建议

### 通用安全原则
1. ✅ **永远使用密码学安全的随机数生成器**
   - 使用`SecureRandom`，不要使用`Random`
   - 使用`RandomUtil`生成密钥、IV、盐值

2. ✅ **每次加密使用不同的随机IV**
   - AES/SM4的CBC、CTR、GCM模式都需要IV
   - 使用`generateIVForCBC()`、`generateIVForGCM()`等方法

3. ✅ **优先选择认证加密模式(GCM)**
   - GCM模式提供加密+完整性验证
   - 防止密文篡改攻击

4. ❌ **禁止使用ECB模式**
   - ECB模式对相同明文块产生相同密文块
   - 容易泄露数据模式，存在严重安全风险

5. ❌ **禁止硬编码密钥**
   - 不要在代码中直接写入密钥
   - 使用配置文件、环境变量或密钥管理服务

### 密钥管理最佳实践

**密钥存储**
- 使用密钥管理服务(KMS)或硬件安全模块(HSM)
- 生产环境禁止在代码或配置文件中明文存储密钥
- 使用环境变量或密钥库（Java KeyStore）

**密钥轮换**
- 定期更换密钥（建议每季度或半年）
- 保留旧密钥一段时间用于解密旧数据
- 建立密钥版本管理机制

**密钥长度推荐**
| 算法 | 最低要求 | 推荐使用 | 高安全场景 |
|------|---------|----------|-----------|
| RSA | 2048位 | 3072位 | 4096位 |
| AES | 128位 | 256位 | 256位 |
| SM2 | 256位（固定） | 256位 | 256位 |
| SM4 | 128位（固定） | 128位 | 128位 |

### 加密模式选择指南

**对称加密模式**
```
推荐顺序（由高到低）：
1. GCM   - 认证加密，最高安全性，性能好
2. CTR   - 流式加密，无需填充，性能好
3. CBC   - 传统模式，需要IV，广泛兼容
4. CFB   - 流式模式，适合流数据
5. OFB   - 流式模式，错误不会传播
❌ ECB   - 不安全，禁止使用（除非兼容旧系统）
```

**非对称加密填充**
```
RSA推荐顺序：
1. OAEPWithSHA-256/384/512 - NIST推荐，抗CCA攻击
2. OAEPPadding - 基础OAEP，使用SHA-1
❌ PKCS1Padding - 已弃用，存在攻击风险
❌ NoPadding - 完全不安全
```

### 常见安全陷阱

❌ **错误示例**
```java
// 1. 使用弱随机数生成器
Random random = new Random();
byte[] key = new byte[16];
random.nextBytes(key);  // ❌ 不安全！

// 2. 重用IV
String iv = "固定的IV值";  // ❌ 不安全！每次加密应使用不同的IV

// 3. 使用ECB模式
AESUtils.encryptECB(data, key);  // ❌ 不安全！

// 4. 硬编码密钥
String key = "MySecretKey123";  // ❌ 不安全！
```

✅ **正确示例**
```java
// 1. 使用密码学安全的随机数生成器
byte[] key = AESUtils.generateKey(256);

// 2. 每次加密生成新的随机IV
String iv = AESUtils.generateIVForGCM();

// 3. 使用GCM认证加密模式
String encrypted = AESUtils.encryptGCM(data, key, iv);

// 4. 从安全配置加载密钥
String key = System.getenv("ENCRYPTION_KEY");
```

---

## 📖 使用示例

### RSA加密示例
```java
// 生成密钥对
RSAKeyPair keyPair = RSAUtils.generateKey(2048);
String publicKey = keyPair.getPublicKey();
String privateKey = keyPair.getPrivateKey();

// 加密（推荐使用OAEP SHA-256）
String plaintext = "Hello World";
String ciphertext = RSAUtils.encryptByPublicKey(plaintext, publicKey);

// 解密
String decrypted = RSAUtils.decryptByPrivateKey(ciphertext, privateKey);

// 签名
String signature = RSAUtils.sign(RSASignType.SHA256withRSA, plaintext, privateKey);

// 验签
boolean valid = RSAUtils.verifySign(RSASignType.SHA256withRSA, plaintext, publicKey, signature);
```

### AES加密示例
```java
// 生成密钥
byte[] key = AESUtils.generateKey(256);

// GCM模式加密（推荐）
String iv = AESUtils.generateIVForGCM();
String ciphertext = AESUtils.encryptGCM(plaintext, new String(Base64.getEncoder().encode(key)), iv);
String decrypted = AESUtils.decryptGCM(ciphertext, new String(Base64.getEncoder().encode(key)), iv);

// CBC模式加密
String ivCBC = AESUtils.generateIVForCBC();
String ciphertextCBC = AESUtils.encrypt(plaintext, new String(Base64.getEncoder().encode(key)), ivCBC);
String decryptedCBC = AESUtils.decrypt(ciphertextCBC, new String(Base64.getEncoder().encode(key)), ivCBC);
```

### SHA散列示例
```java
// SHA-256散列
String hash = SHAUtils.sha256("Hello World");

// SHA3-256散列（JDK9+）
String hash3 = SHAUtils.sha3_256("Hello World");
```

### HMAC示例
```java
// 生成HMAC密钥
byte[] key = HmacUtils.generateHmacSHA256Key();

// HmacSHA256
String hmac = HmacUtils.hmacSHA256("Hello World", new String(key));
```

---

## 📦 依赖说明

### 核心依赖
- **BouncyCastle** - 提供完整的加密算法支持
- **Apache Commons Codec** - 提供Base64、Hex等编码工具
- **Apache Commons Lang3** - 提供字符串处理工具

### 环境要求
- **JDK版本**：Java 8+
- **SHA3算法**：需要JDK 9+

---

## 🤝 贡献指南

欢迎提交Issue和Pull Request！

### 代码规范
- 类中仅保留精简必要的注释
- JavaDoc、算法介绍、模式说明统一放入README
- 遵循现有代码风格

---

