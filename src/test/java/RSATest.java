import com.lzc.lib.util.cipher.asymmetry.RSAUtils;
import com.lzc.lib.util.cipher.constant.Mode;
import com.lzc.lib.util.cipher.constant.Padding;
import com.lzc.lib.util.cipher.pojo.RSAKeyPair;
import org.apache.commons.codec.binary.Base64;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

/**
 * RSAUtils 测试类
 * 包含以下测试内容：
 * - 密钥导出导入功能（DER 和 PEM 格式）
 * - 默认方法测试（OAEP SHA-256，推荐）
 * - OAEP SHA-1 填充方式测试（传统）
 * - OAEP SHA-256/384/512 填充方式测试（现代标准）
 * - PKCS1 填充方式测试（传统，已弃用）
 * - PKCS#1 v1.5 填充方式测试（传统，已弃用）
 * - 填充方式兼容性测试
 * - 字节数组加解密测试
 * - 私钥加密、公钥解密测试
 *
 * @author lzc
 * 2025/11/03
 */
public class RSATest {

    private String testData = "Hello, RSA Key Import/Export Test!";
    private RSAKeyPair keyPair;
    private String publicKeyBase64;
    private String privateKeyBase64;

    @Before
    public void setup() {
        // 生成测试用的密钥对
        keyPair = RSAUtils.generateKey(2048);
        publicKeyBase64 = keyPair.getPublicKey();
        privateKeyBase64 = keyPair.getPrivateKey();
    }

    /**
     * 测试公钥导出为 DER 格式
     */
    @Test
    public void testExportPublicKeyToDER() {
        System.out.println("=== 测试公钥导出为 DER 格式 ===");

        byte[] derBytes = RSAUtils.exportPublicKeyToDER(publicKeyBase64);
        Assert.assertNotNull("DER 格式公钥不应为空", derBytes);
        Assert.assertTrue("DER 格式公钥应有内容", derBytes.length > 0);

        System.out.println("DER 格式公钥长度: " + derBytes.length + " 字节");
        System.out.println("✓ 公钥导出为 DER 格式测试通过\n");
    }

    /**
     * 测试私钥导出为 DER 格式
     */
    @Test
    public void testExportPrivateKeyToDER() {
        System.out.println("=== 测试私钥导出为 DER 格式 ===");

        byte[] derBytes = RSAUtils.exportPrivateKeyToDER(privateKeyBase64);
        Assert.assertNotNull("DER 格式私钥不应为空", derBytes);
        Assert.assertTrue("DER 格式私钥应有内容", derBytes.length > 0);

        System.out.println("DER 格式私钥长度: " + derBytes.length + " 字节");
        System.out.println("✓ 私钥导出为 DER 格式测试通过\n");
    }

    /**
     * 测试公钥导出为 PEM 格式
     */
    @Test
    public void testExportPublicKeyToPEM() {
        System.out.println("=== 测试公钥导出为 PEM 格式 ===");

        String pemString = RSAUtils.exportPublicKeyToPEM(publicKeyBase64);
        Assert.assertNotNull("PEM 格式公钥不应为空", pemString);
        Assert.assertTrue("PEM 应包含头部标记", pemString.contains("-----BEGIN PUBLIC KEY-----"));
        Assert.assertTrue("PEM 应包含尾部标记", pemString.contains("-----END PUBLIC KEY-----"));

        System.out.println("PEM 格式公钥:\n" + pemString);
        System.out.println("✓ 公钥导出为 PEM 格式测试通过\n");
    }

    /**
     * 测试私钥导出为 PEM 格式
     */
    @Test
    public void testExportPrivateKeyToPEM() {
        System.out.println("=== 测试私钥导出为 PEM 格式 ===");

        String pemString = RSAUtils.exportPrivateKeyToPEM(privateKeyBase64);
        Assert.assertNotNull("PEM 格式私钥不应为空", pemString);
        Assert.assertTrue("PEM 应包含头部标记", pemString.contains("-----BEGIN PRIVATE KEY-----"));
        Assert.assertTrue("PEM 应包含尾部标记", pemString.contains("-----END PRIVATE KEY-----"));

        System.out.println("PEM 格式私钥:\n" + pemString);
        System.out.println("✓ 私钥导出为 PEM 格式测试通过\n");
    }

    /**
     * 测试从 DER 格式导入公钥
     */
    @Test
    public void testImportPublicKeyFromDER() {
        System.out.println("=== 测试从 DER 格式导入公钥 ===");

        // 导出为 DER
        byte[] derBytes = RSAUtils.exportPublicKeyToDER(publicKeyBase64);

        // 从 DER 导入
        RSAPublicKey importedKey = RSAUtils.importPublicKeyFromDER(derBytes);
        Assert.assertNotNull("导入的公钥不应为空", importedKey);

        // 验证导入的密钥可以正常使用（直接使用原始公钥字符串）
        String encrypted = RSAUtils.encryptByPublicKey(testData, publicKeyBase64);
        String decrypted = RSAUtils.decryptByPrivateKey(encrypted, privateKeyBase64);
        Assert.assertEquals("加解密后应该与原文一致", testData, decrypted);

        // 验证导入的密钥与原始密钥的编码一致
        Assert.assertArrayEquals("导入的公钥编码应该与原始公钥编码一致",
            Base64.decodeBase64(publicKeyBase64), importedKey.getEncoded());

        System.out.println("原文: " + testData);
        System.out.println("解密: " + decrypted);
        System.out.println("✓ 从 DER 格式导入公钥测试通过\n");
    }

    /**
     * 测试从 DER 格式导入私钥
     */
    @Test
    public void testImportPrivateKeyFromDER() {
        System.out.println("=== 测试从 DER 格式导入私钥 ===");

        // 导出为 DER
        byte[] derBytes = RSAUtils.exportPrivateKeyToDER(privateKeyBase64);

        // 从 DER 导入
        RSAPrivateKey importedKey = RSAUtils.importPrivateKeyFromDER(derBytes);
        Assert.assertNotNull("导入的私钥不应为空", importedKey);

        // 验证导入的密钥可以正常使用（直接使用原始私钥字符串）
        String encrypted = RSAUtils.encryptByPublicKey(testData, publicKeyBase64);
        String decrypted = RSAUtils.decryptByPrivateKey(encrypted, privateKeyBase64);
        Assert.assertEquals("加解密后应该与原文一致", testData, decrypted);

        // 验证导入的密钥与原始密钥的编码一致
        Assert.assertArrayEquals("导入的私钥编码应该与原始私钥编码一致",
            Base64.decodeBase64(privateKeyBase64), importedKey.getEncoded());

        System.out.println("原文: " + testData);
        System.out.println("解密: " + decrypted);
        System.out.println("✓ 从 DER 格式导入私钥测试通过\n");
    }

    /**
     * 测试从 PEM 格式导入公钥
     */
    @Test
    public void testImportPublicKeyFromPEM() {
        System.out.println("=== 测试从 PEM 格式导入公钥 ===");

        // 导出为 PEM
        String pemString = RSAUtils.exportPublicKeyToPEM(publicKeyBase64);

        // 从 PEM 导入
        RSAPublicKey importedKey = RSAUtils.importPublicKeyFromPEM(pemString);
        Assert.assertNotNull("导入的公钥不应为空", importedKey);

        // 验证导入的密钥可以正常使用（直接使用原始公钥字符串）
        String encrypted = RSAUtils.encryptByPublicKey(testData, publicKeyBase64);
        String decrypted = RSAUtils.decryptByPrivateKey(encrypted, privateKeyBase64);
        Assert.assertEquals("加解密后应该与原文一致", testData, decrypted);

        // 验证导入的密钥与原始密钥的编码一致
        Assert.assertArrayEquals("导入的公钥编码应该与原始公钥编码一致",
            Base64.decodeBase64(publicKeyBase64), importedKey.getEncoded());

        System.out.println("原文: " + testData);
        System.out.println("解密: " + decrypted);
        System.out.println("✓ 从 PEM 格式导入公钥测试通过\n");
    }

    /**
     * 测试从 PEM 格式导入私钥
     */
    @Test
    public void testImportPrivateKeyFromPEM() {
        System.out.println("=== 测试从 PEM 格式导入私钥 ===");

        // 导出为 PEM
        String pemString = RSAUtils.exportPrivateKeyToPEM(privateKeyBase64);

        // 从 PEM 导入
        RSAPrivateKey importedKey = RSAUtils.importPrivateKeyFromPEM(pemString);
        Assert.assertNotNull("导入的私钥不应为空", importedKey);

        // 验证导入的密钥可以正常使用（直接使用原始私钥字符串）
        String encrypted = RSAUtils.encryptByPublicKey(testData, publicKeyBase64);
        String decrypted = RSAUtils.decryptByPrivateKey(encrypted, privateKeyBase64);
        Assert.assertEquals("加解密后应该与原文一致", testData, decrypted);

        // 验证导入的密钥与原始密钥的编码一致
        Assert.assertArrayEquals("导入的私钥编码应该与原始私钥编码一致",
            Base64.decodeBase64(privateKeyBase64), importedKey.getEncoded());

        System.out.println("原文: " + testData);
        System.out.println("解密: " + decrypted);
        System.out.println("✓ 从 PEM 格式导入私钥测试通过\n");
    }

    /**
     * 测试公钥文件导出导入（DER 格式）
     */
    @Test
    public void testPublicKeyDERFile() {
        System.out.println("=== 测试公钥文件导出导入（DER 格式）===");

        String filePath = "test_rsa_public.der";

        try {
            // 导出到文件
            RSAUtils.exportPublicKeyToDERFile(publicKeyBase64, filePath);
            System.out.println("已导出公钥到文件: " + filePath);

            // 从文件导入
            RSAPublicKey importedKey = RSAUtils.importPublicKeyFromDERFile(filePath);
            Assert.assertNotNull("导入的公钥不应为空", importedKey);

            // 验证
            byte[] original = RSAUtils.exportPublicKeyToDER(publicKeyBase64);
            byte[] imported = importedKey.getEncoded();
            Assert.assertTrue("导入导出的公钥应该一致", Arrays.equals(original, imported));

            System.out.println("✓ 公钥 DER 文件导出导入测试通过\n");
        } finally {
            // 清理测试文件
            new File(filePath).delete();
        }
    }

    /**
     * 测试私钥文件导出导入（DER 格式）
     */
    @Test
    public void testPrivateKeyDERFile() {
        System.out.println("=== 测试私钥文件导出导入（DER 格式）===");

        String filePath = "test_rsa_private.der";

        try {
            // 导出到文件
            RSAUtils.exportPrivateKeyToDERFile(privateKeyBase64, filePath);
            System.out.println("已导出私钥到文件: " + filePath);

            // 从文件导入
            RSAPrivateKey importedKey = RSAUtils.importPrivateKeyFromDERFile(filePath);
            Assert.assertNotNull("导入的私钥不应为空", importedKey);

            // 验证
            byte[] original = RSAUtils.exportPrivateKeyToDER(privateKeyBase64);
            byte[] imported = importedKey.getEncoded();
            Assert.assertTrue("导入导出的私钥应该一致", Arrays.equals(original, imported));

            System.out.println("✓ 私钥 DER 文件导出导入测试通过\n");
        } finally {
            // 清理测试文件
            new File(filePath).delete();
        }
    }

    /**
     * 测试公钥文件导出导入（PEM 格式）
     */
    @Test
    public void testPublicKeyPEMFile() {
        System.out.println("=== 测试公钥文件导出导入（PEM 格式）===");

        String filePath = "test_rsa_public.pem";

        try {
            // 导出到文件
            RSAUtils.exportPublicKeyToPEMFile(publicKeyBase64, filePath);
            System.out.println("已导出公钥到文件: " + filePath);

            // 从文件导入
            RSAPublicKey importedKey = RSAUtils.importPublicKeyFromPEMFile(filePath);
            Assert.assertNotNull("导入的公钥不应为空", importedKey);

            // 验证
            byte[] original = RSAUtils.exportPublicKeyToDER(publicKeyBase64);
            byte[] imported = importedKey.getEncoded();
            Assert.assertTrue("导入导出的公钥应该一致", Arrays.equals(original, imported));

            System.out.println("✓ 公钥 PEM 文件导出导入测试通过\n");
        } finally {
            // 清理测试文件
            new File(filePath).delete();
        }
    }

    /**
     * 测试私钥文件导出导入（PEM 格式）
     */
    @Test
    public void testPrivateKeyPEMFile() {
        System.out.println("=== 测试私钥文件导出导入（PEM 格式）===");

        String filePath = "test_rsa_private.pem";

        try {
            // 导出到文件
            RSAUtils.exportPrivateKeyToPEMFile(privateKeyBase64, filePath);
            System.out.println("已导出私钥到文件: " + filePath);

            // 从文件导入
            RSAPrivateKey importedKey = RSAUtils.importPrivateKeyFromPEMFile(filePath);
            Assert.assertNotNull("导入的私钥不应为空", importedKey);

            // 验证
            byte[] original = RSAUtils.exportPrivateKeyToDER(privateKeyBase64);
            byte[] imported = importedKey.getEncoded();
            Assert.assertTrue("导入导出的私钥应该一致", Arrays.equals(original, imported));

            System.out.println("✓ 私钥 PEM 文件导出导入测试通过\n");
        } finally {
            // 清理测试文件
            new File(filePath).delete();
        }
    }

    /**
     * 测试 DER 和 PEM 互转
     */
    @Test
    public void testDERAndPEMConversion() {
        System.out.println("=== 测试 DER 和 PEM 互转 ===");

        // 公钥：DER -> PEM -> DER
        byte[] publicDER1 = RSAUtils.exportPublicKeyToDER(publicKeyBase64);
        String publicPEM = RSAUtils.exportPublicKeyToPEM(publicKeyBase64);
        RSAPublicKey publicKey = RSAUtils.importPublicKeyFromPEM(publicPEM);
        byte[] publicDER2 = publicKey.getEncoded();
        Assert.assertTrue("公钥 DER-PEM-DER 转换应保持一致", Arrays.equals(publicDER1, publicDER2));
        System.out.println("✓ 公钥 DER-PEM 互转测试通过");

        // 私钥：DER -> PEM -> DER
        byte[] privateDER1 = RSAUtils.exportPrivateKeyToDER(privateKeyBase64);
        String privatePEM = RSAUtils.exportPrivateKeyToPEM(privateKeyBase64);
        RSAPrivateKey privateKey = RSAUtils.importPrivateKeyFromPEM(privatePEM);
        byte[] privateDER2 = privateKey.getEncoded();
        Assert.assertTrue("私钥 DER-PEM-DER 转换应保持一致", Arrays.equals(privateDER1, privateDER2));
        System.out.println("✓ 私钥 DER-PEM 互转测试通过\n");
    }

    // ========== 以下是填充方式测试 ==========

    /**
     * 测试默认方法（OAEP SHA-256，推荐）
     */
    @Test
    public void testOAEPPadding() {
        System.out.println("=== 测试默认方法（OAEP SHA-256，推荐） ===");

        String plaintext = "Hello RSA OAEP!";

        // 测试默认方法（现在使用 OAEP SHA-256）
        String encrypted = RSAUtils.encryptByPublicKey(plaintext, publicKeyBase64);
        System.out.println("原文: " + plaintext);
        System.out.println("密文: " + encrypted);

        String decrypted = RSAUtils.decryptByPrivateKey(encrypted, privateKeyBase64);
        System.out.println("解密: " + decrypted);
        Assert.assertEquals("默认方法（OAEP SHA-256）解密后应该与原文一致", plaintext, decrypted);

        // 验证默认方法与显式 OAEP SHA-256 方法兼容
        String encrypted2 = RSAUtils.encryptByPublicKeyOAEPSHA256(plaintext, publicKeyBase64);
        String decrypted2 = RSAUtils.decryptByPrivateKey(encrypted2, privateKeyBase64);
        Assert.assertEquals("默认方法应该能解密 OAEP SHA-256 的密文", plaintext, decrypted2);

        // 测试显式 OAEP SHA-1 方法（传统）
        String encrypted3 = RSAUtils.encryptByPublicKeyOAEP(plaintext, publicKeyBase64);
        String decrypted3 = RSAUtils.decryptByPrivateKeyOAEP(encrypted3, privateKeyBase64);
        Assert.assertEquals("显式 OAEP SHA-1 方法解密后应该与原文一致", plaintext, decrypted3);

        System.out.println("✓ 默认方法（OAEP SHA-256）测试通过\n");
    }

    /**
     * 测试 PKCS1 填充方式（传统，已弃用）
     */
    @Test
    @SuppressWarnings("deprecation")
    public void testPKCS1Padding() {
        System.out.println("=== 测试 PKCS1 填充方式（传统，已弃用） ===");

        String plaintext = "Hello RSA PKCS1!";

        // 测试弃用的 PKCS1 方法（用于兼容旧系统）
        String encrypted = RSAUtils.encryptByPublicKeyPKCS1(plaintext, publicKeyBase64);
        System.out.println("原文: " + plaintext);
        System.out.println("密文: " + encrypted);

        String decrypted = RSAUtils.decryptByPrivateKeyPKCS1(encrypted, privateKeyBase64);
        System.out.println("解密: " + decrypted);
        Assert.assertEquals("PKCS1 解密后应该与原文一致", plaintext, decrypted);

        System.out.println("⚠️ PKCS1 填充测试通过（但不推荐使用）\n");
    }

    /**
     * 测试 PKCS#1 v1.5 填充方式（传统，已弃用）
     */
    @Test
    @SuppressWarnings("deprecation")
    public void testPKCS1V15Padding() {
        System.out.println("=== 测试 PKCS#1 v1.5 填充方式（传统，已弃用） ===");

        String plaintext = "Hello RSA PKCS#1 v1.5!";

        // 测试 PKCS1V15 方法（应该与 PKCS1 方法等价）
        String encrypted = RSAUtils.encryptByPublicKeyPKCS1V15(plaintext, publicKeyBase64);
        System.out.println("原文: " + plaintext);
        System.out.println("密文: " + encrypted);

        String decrypted = RSAUtils.decryptByPrivateKeyPKCS1V15(encrypted, privateKeyBase64);
        System.out.println("解密: " + decrypted);
        Assert.assertEquals("PKCS#1 v1.5 解密后应该与原文一致", plaintext, decrypted);

        // 验证 PKCS1V15 方法与 PKCS1 方法的兼容性
        String pkcs1Encrypted = RSAUtils.encryptByPublicKeyPKCS1(plaintext, publicKeyBase64);
        String pkcs1v15Decrypted = RSAUtils.decryptByPrivateKeyPKCS1V15(pkcs1Encrypted, privateKeyBase64);
        Assert.assertEquals("PKCS1V15 应该能解密 PKCS1 的密文", plaintext, pkcs1v15Decrypted);

        String pkcs1v15Encrypted = RSAUtils.encryptByPublicKeyPKCS1V15(plaintext, publicKeyBase64);
        String pkcs1Decrypted = RSAUtils.decryptByPrivateKeyPKCS1(pkcs1v15Encrypted, privateKeyBase64);
        Assert.assertEquals("PKCS1 应该能解密 PKCS1V15 的密文", plaintext, pkcs1Decrypted);

        System.out.println("✓ PKCS1V15 与 PKCS1 兼容性验证通过");
        System.out.println("⚠️ PKCS#1 v1.5 填充测试通过（但不推荐使用）\n");
    }

    /**
     * 测试 PKCS#1 v1.5 字节数组加解密
     */
    @Test
    @SuppressWarnings("deprecation")
    public void testPKCS1V15ByteArray() {
        System.out.println("=== 测试 PKCS#1 v1.5 字节数组加解密 ===");

        byte[] plaintext = "Hello RSA PKCS#1 v1.5 Bytes!".getBytes();

        // 字节数组加解密
        byte[] encrypted = RSAUtils.encryptByPublicKeyPKCS1V15(plaintext, Base64.decodeBase64(publicKeyBase64));
        byte[] decrypted = RSAUtils.decryptByPrivateKeyPKCS1V15(encrypted, privateKeyBase64);

        Assert.assertArrayEquals("PKCS#1 v1.5 字节数组解密后应该与原文一致", plaintext, decrypted);

        System.out.println("原文: " + new String(plaintext));
        System.out.println("解密: " + new String(decrypted));
        System.out.println("⚠️ PKCS#1 v1.5 字节数组测试通过（但不推荐使用）\n");
    }

    /**
     * 测试 PKCS#1 v1.5 私钥加密、公钥解密
     */
    @Test
    @SuppressWarnings("deprecation")
    public void testPKCS1V15PrivateEncryptPublicDecrypt() {
        System.out.println("=== 测试 PKCS#1 v1.5 私钥加密、公钥解密 ===");

        String plaintext = "Test PKCS#1 v1.5 private encrypt!";

        // 私钥加密
        String encrypted = RSAUtils.encryptByPrivateKeyPKCS1V15(plaintext, privateKeyBase64);
        System.out.println("原文: " + plaintext);
        System.out.println("私钥加密密文 (PKCS#1 v1.5): " + encrypted);

        // 公钥解密
        String decrypted = RSAUtils.decryptByPublicKeyPKCS1V15(encrypted, publicKeyBase64);
        System.out.println("公钥解密: " + decrypted);

        Assert.assertEquals("PKCS#1 v1.5 私钥加密、公钥解密后应该与原文一致", plaintext, decrypted);

        System.out.println("⚠️ PKCS#1 v1.5 私钥加密、公钥解密测试通过（但不推荐使用）\n");
    }

    /**
     * 测试 OAEP 和 PKCS1 不兼容
     */
    @Test
    @SuppressWarnings("deprecation")
    public void testPaddingIncompatibility() {
        System.out.println("=== 测试 OAEP 和 PKCS1 不兼容 ===");

        String plaintext = "Test padding incompatibility";

        // OAEP 加密的数据不能用 PKCS1 解密
        String oaepEncrypted = RSAUtils.encryptByPublicKeyOAEP(plaintext, publicKeyBase64);

        try {
            RSAUtils.decryptByPrivateKeyPKCS1(oaepEncrypted, privateKeyBase64);
            Assert.fail("OAEP 加密的数据不应该能用 PKCS1 解密");
        } catch (Exception e) {
            System.out.println("✓ 验证通过：OAEP 加密的数据无法用 PKCS1 解密");
        }

        // PKCS1 加密的数据不能用 OAEP 解密
        String pkcs1Encrypted = RSAUtils.encryptByPublicKeyPKCS1(plaintext, publicKeyBase64);

        try {
            RSAUtils.decryptByPrivateKeyOAEP(pkcs1Encrypted, privateKeyBase64);
            Assert.fail("PKCS1 加密的数据不应该能用 OAEP 解密");
        } catch (Exception e) {
            System.out.println("✓ 验证通过：PKCS1 加密的数据无法用 OAEP 解密");
        }

        System.out.println("✓ 填充方式不兼容性测试通过\n");
    }

    /**
     * 测试字节数组加解密（OAEP SHA-256，默认方法）
     */
    @Test
    public void testByteArrayEncryptionOAEP() {
        System.out.println("=== 测试字节数组加解密（OAEP SHA-256，默认方法） ===");

        byte[] plaintext = "Hello RSA Bytes!".getBytes();

        // 字节数组加解密（默认方法使用 OAEP SHA-256）
        byte[] encrypted = RSAUtils.encryptByPublicKey(plaintext, Base64.decodeBase64(publicKeyBase64));
        byte[] decrypted = RSAUtils.decryptByPrivateKey(encrypted, privateKeyBase64);

        Assert.assertArrayEquals("字节数组解密后应该与原文一致", plaintext, decrypted);

        System.out.println("原文: " + new String(plaintext));
        System.out.println("解密: " + new String(decrypted));
        System.out.println("✓ 字节数组加解密（OAEP SHA-256）测试通过\n");
    }

    /**
     * 测试私钥加密、公钥解密（OAEP SHA-256，默认方法）
     */
    @Test
    public void testPrivateEncryptPublicDecrypt() {
        System.out.println("=== 测试私钥加密、公钥解密（OAEP SHA-256，默认方法） ===");

        String plaintext = "Test private encrypt!";

        // 私钥加密（默认方法使用 OAEP SHA-256）
        String encrypted = RSAUtils.encryptByPrivateKey(plaintext, privateKeyBase64);
        System.out.println("原文: " + plaintext);
        System.out.println("私钥加密密文: " + encrypted);

        // 公钥解密
        String decrypted = RSAUtils.decryptByPublicKey(encrypted, publicKeyBase64);
        System.out.println("公钥解密: " + decrypted);

        Assert.assertEquals("私钥加密、公钥解密后应该与原文一致", plaintext, decrypted);

        System.out.println("✓ 私钥加密、公钥解密（OAEP SHA-256）测试通过\n");
    }

    // ========== 以下是 OAEP 变体测试（SHA-256/384/512） ==========

    /**
     * 测试 OAEP with SHA-256 填充（现代推荐标准）
     */
    @Test
    public void testOAEPSHA256Padding() {
        System.out.println("=== 测试 OAEP with SHA-256 填充（现代推荐标准） ===");

        String plaintext = "Hello RSA OAEP SHA-256!";

        // 公钥加密、私钥解密
        String encrypted = RSAUtils.encryptByPublicKeyOAEPSHA256(plaintext, publicKeyBase64);
        System.out.println("原文: " + plaintext);
        System.out.println("密文: " + encrypted);

        String decrypted = RSAUtils.decryptByPrivateKeyOAEPSHA256(encrypted, privateKeyBase64);
        System.out.println("解密: " + decrypted);
        Assert.assertEquals("OAEP SHA-256 解密后应该与原文一致", plaintext, decrypted);

        // 字节数组加解密
        byte[] plaintextBytes = plaintext.getBytes();
        byte[] encryptedBytes = RSAUtils.encryptByPublicKeyOAEPSHA256(plaintextBytes, Base64.decodeBase64(publicKeyBase64));
        byte[] decryptedBytes = RSAUtils.decryptByPrivateKeyOAEPSHA256(encryptedBytes, privateKeyBase64);
        Assert.assertArrayEquals("字节数组 OAEP SHA-256 解密后应该与原文一致", plaintextBytes, decryptedBytes);

        System.out.println("✓ OAEP with SHA-256 填充测试通过\n");
    }

    /**
     * 测试 OAEP with SHA-384 填充（高安全场景）
     */
    @Test
    public void testOAEPSHA384Padding() {
        System.out.println("=== 测试 OAEP with SHA-384 填充（高安全场景） ===");

        String plaintext = "Hello RSA OAEP SHA-384!";

        // 公钥加密、私钥解密
        String encrypted = RSAUtils.encryptByPublicKeyOAEPSHA384(plaintext, publicKeyBase64);
        System.out.println("原文: " + plaintext);
        System.out.println("密文: " + encrypted);

        String decrypted = RSAUtils.decryptByPrivateKeyOAEPSHA384(encrypted, privateKeyBase64);
        System.out.println("解密: " + decrypted);
        Assert.assertEquals("OAEP SHA-384 解密后应该与原文一致", plaintext, decrypted);

        // 字节数组加解密
        byte[] plaintextBytes = plaintext.getBytes();
        byte[] encryptedBytes = RSAUtils.encryptByPublicKeyOAEPSHA384(plaintextBytes, Base64.decodeBase64(publicKeyBase64));
        byte[] decryptedBytes = RSAUtils.decryptByPrivateKeyOAEPSHA384(encryptedBytes, privateKeyBase64);
        Assert.assertArrayEquals("字节数组 OAEP SHA-384 解密后应该与原文一致", plaintextBytes, decryptedBytes);

        System.out.println("✓ OAEP with SHA-384 填充测试通过\n");
    }

    /**
     * 测试 OAEP with SHA-512 填充（高安全场景）
     */
    @Test
    public void testOAEPSHA512Padding() {
        System.out.println("=== 测试 OAEP with SHA-512 填充（高安全场景） ===");

        String plaintext = "Hello RSA OAEP SHA-512!";

        // 公钥加密、私钥解密
        String encrypted = RSAUtils.encryptByPublicKeyOAEPSHA512(plaintext, publicKeyBase64);
        System.out.println("原文: " + plaintext);
        System.out.println("密文: " + encrypted);

        String decrypted = RSAUtils.decryptByPrivateKeyOAEPSHA512(encrypted, privateKeyBase64);
        System.out.println("解密: " + decrypted);
        Assert.assertEquals("OAEP SHA-512 解密后应该与原文一致", plaintext, decrypted);

        // 字节数组加解密
        byte[] plaintextBytes = plaintext.getBytes();
        byte[] encryptedBytes = RSAUtils.encryptByPublicKeyOAEPSHA512(plaintextBytes, Base64.decodeBase64(publicKeyBase64));
        byte[] decryptedBytes = RSAUtils.decryptByPrivateKeyOAEPSHA512(encryptedBytes, privateKeyBase64);
        Assert.assertArrayEquals("字节数组 OAEP SHA-512 解密后应该与原文一致", plaintextBytes, decryptedBytes);

        System.out.println("✓ OAEP with SHA-512 填充测试通过\n");
    }

    /**
     * 测试不同 OAEP 变体之间的不兼容性
     */
    @Test
    public void testOAEPVariantsIncompatibility() {
        System.out.println("=== 测试不同 OAEP 变体之间的不兼容性 ===");

        String plaintext = "Test OAEP variants incompatibility";

        // 默认方法（SHA-256）加密的数据不能用 SHA-1 解密
        String defaultEncrypted = RSAUtils.encryptByPublicKey(plaintext, publicKeyBase64);

        try {
            RSAUtils.decryptByPrivateKeyOAEP(defaultEncrypted, privateKeyBase64);
            Assert.fail("默认方法（SHA-256）加密的数据不应该能用 SHA-1 OAEP 解密");
        } catch (Exception e) {
            System.out.println("✓ 验证通过：默认方法（SHA-256）加密的数据无法用 SHA-1 OAEP 解密");
        }

        // SHA-1 加密的数据不能用默认方法（SHA-256）解密
        String sha1Encrypted = RSAUtils.encryptByPublicKeyOAEP(plaintext, publicKeyBase64);

        try {
            RSAUtils.decryptByPrivateKey(sha1Encrypted, privateKeyBase64);
            Assert.fail("SHA-1 OAEP 加密的数据不应该能用默认方法（SHA-256）解密");
        } catch (Exception e) {
            System.out.println("✓ 验证通过：SHA-1 OAEP 加密的数据无法用默认方法（SHA-256）解密");
        }

        // SHA-384 加密的数据不能用 SHA-256 解密
        String sha384Encrypted = RSAUtils.encryptByPublicKeyOAEPSHA384(plaintext, publicKeyBase64);

        try {
            RSAUtils.decryptByPrivateKeyOAEPSHA256(sha384Encrypted, privateKeyBase64);
            Assert.fail("SHA-384 OAEP 加密的数据不应该能用 SHA-256 OAEP 解密");
        } catch (Exception e) {
            System.out.println("✓ 验证通过：SHA-384 OAEP 加密的数据无法用 SHA-256 OAEP 解密");
        }

        // SHA-512 加密的数据不能用 SHA-384 解密
        String sha512Encrypted = RSAUtils.encryptByPublicKeyOAEPSHA512(plaintext, publicKeyBase64);

        try {
            RSAUtils.decryptByPrivateKeyOAEPSHA384(sha512Encrypted, privateKeyBase64);
            Assert.fail("SHA-512 OAEP 加密的数据不应该能用 SHA-384 OAEP 解密");
        } catch (Exception e) {
            System.out.println("✓ 验证通过：SHA-512 OAEP 加密的数据无法用 SHA-384 OAEP 解密");
        }

        System.out.println("✓ OAEP 变体不兼容性测试通过\n");
    }

    /**
     * 测试私钥加密、公钥解密（OAEP with SHA-256）
     */
    @Test
    public void testPrivateEncryptPublicDecryptOAEPSHA256() {
        System.out.println("=== 测试私钥加密、公钥解密（OAEP with SHA-256） ===");

        String plaintext = "Test private encrypt with SHA-256!";

        // 私钥加密
        String encrypted = RSAUtils.encryptByPrivateKeyOAEPSHA256(plaintext, privateKeyBase64);
        System.out.println("原文: " + plaintext);
        System.out.println("私钥加密密文 (SHA-256): " + encrypted);

        // 公钥解密
        String decrypted = RSAUtils.decryptByPublicKeyOAEPSHA256(encrypted, publicKeyBase64);
        System.out.println("公钥解密: " + decrypted);

        Assert.assertEquals("私钥加密、公钥解密（SHA-256）后应该与原文一致", plaintext, decrypted);

        System.out.println("✓ 私钥加密、公钥解密（OAEP with SHA-256）测试通过\n");
    }

    /**
     * 测试私钥加密、公钥解密（OAEP with SHA-384）
     */
    @Test
    public void testPrivateEncryptPublicDecryptOAEPSHA384() {
        System.out.println("=== 测试私钥加密、公钥解密（OAEP with SHA-384） ===");

        String plaintext = "Test private encrypt with SHA-384!";

        // 私钥加密
        String encrypted = RSAUtils.encryptByPrivateKeyOAEPSHA384(plaintext, privateKeyBase64);
        System.out.println("原文: " + plaintext);
        System.out.println("私钥加密密文 (SHA-384): " + encrypted);

        // 公钥解密
        String decrypted = RSAUtils.decryptByPublicKeyOAEPSHA384(encrypted, publicKeyBase64);
        System.out.println("公钥解密: " + decrypted);

        Assert.assertEquals("私钥加密、公钥解密（SHA-384）后应该与原文一致", plaintext, decrypted);

        System.out.println("✓ 私钥加密、公钥解密（OAEP with SHA-384）测试通过\n");
    }

    /**
     * 测试私钥加密、公钥解密（OAEP with SHA-512）
     */
    @Test
    public void testPrivateEncryptPublicDecryptOAEPSHA512() {
        System.out.println("=== 测试私钥加密、公钥解密（OAEP with SHA-512） ===");

        String plaintext = "Test private encrypt with SHA-512!";

        // 私钥加密
        String encrypted = RSAUtils.encryptByPrivateKeyOAEPSHA512(plaintext, privateKeyBase64);
        System.out.println("原文: " + plaintext);
        System.out.println("私钥加密密文 (SHA-512): " + encrypted);

        // 公钥解密
        String decrypted = RSAUtils.decryptByPublicKeyOAEPSHA512(encrypted, publicKeyBase64);
        System.out.println("公钥解密: " + decrypted);

        Assert.assertEquals("私钥加密、公钥解密（SHA-512）后应该与原文一致", plaintext, decrypted);

        System.out.println("✓ 私钥加密、公钥解密（OAEP with SHA-512）测试通过\n");
    }

    /**
     * 综合测试
     */
    @Test
    public void testAll() {
        System.out.println("\n========== RSAUtils 综合测试 ==========\n");

        // 密钥导出导入测试
        testExportPublicKeyToDER();
        testExportPrivateKeyToDER();
        testExportPublicKeyToPEM();
        testExportPrivateKeyToPEM();
        testImportPublicKeyFromDER();
        testImportPrivateKeyFromDER();
        testImportPublicKeyFromPEM();
        testImportPrivateKeyFromPEM();
        testPublicKeyDERFile();
        testPrivateKeyDERFile();
        testPublicKeyPEMFile();
        testPrivateKeyPEMFile();
        testDERAndPEMConversion();

        // 填充方式测试
        testOAEPPadding();
        testPKCS1Padding();
        testPKCS1V15Padding();
        testPKCS1V15ByteArray();
        testPKCS1V15PrivateEncryptPublicDecrypt();
        testPaddingIncompatibility();
        testByteArrayEncryptionOAEP();
        testPrivateEncryptPublicDecrypt();

        // OAEP 变体测试（SHA-256/384/512）
        testOAEPSHA256Padding();
        testOAEPSHA384Padding();
        testOAEPSHA512Padding();
        testOAEPVariantsIncompatibility();
        testPrivateEncryptPublicDecryptOAEPSHA256();
        testPrivateEncryptPublicDecryptOAEPSHA384();
        testPrivateEncryptPublicDecryptOAEPSHA512();

        System.out.println("========== 所有测试通过 ==========\n");
    }

}
