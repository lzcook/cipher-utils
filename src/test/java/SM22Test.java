import com.dxy.library.util.cipher.asymmetry.SM22Utils;
import com.dxy.library.util.cipher.asymmetry.SM2Utils;
import com.dxy.library.util.cipher.pojo.SM2KeyPair;
import org.apache.commons.codec.binary.Base64;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;

/**
 * SM22Utils 测试类
 * 测试密钥导出导入功能（DER 和 PEM 格式）
 *
 * @author duanxinyuan
 * 2025/11/03
 */
public class SM22Test {

    private String testData = "Hello, SM2 Key Import/Export Test!";
    private SM2KeyPair keyPair;
    private String publicKeyBase64;
    private String privateKeyBase64;

    @Before
    public void setup() {
        // 生成测试用的密钥对
        keyPair = SM2Utils.generateKey(256);
        publicKeyBase64 = keyPair.getPublicKey();
        privateKeyBase64 = keyPair.getPrivateKey();
    }

    /**
     * 测试公钥导出为 DER 格式
     */
    @Test
    public void testExportPublicKeyToDER() {
        System.out.println("=== 测试公钥导出为 DER 格式 ===");

        byte[] derBytes = SM22Utils.exportPublicKeyToDER(publicKeyBase64);
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

        byte[] derBytes = SM22Utils.exportPrivateKeyToDER(privateKeyBase64);
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

        String pemString = SM22Utils.exportPublicKeyToPEM(publicKeyBase64);
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

        String pemString = SM22Utils.exportPrivateKeyToPEM(privateKeyBase64);
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
        byte[] derBytes = SM22Utils.exportPublicKeyToDER(publicKeyBase64);

        // 从 DER 导入
        ECPublicKey importedKey = SM22Utils.importPublicKeyFromDER(derBytes);
        Assert.assertNotNull("导入的公钥不应为空", importedKey);

        // 验证导入的密钥可以正常使用
        String encrypted = SM2Utils.encrypt(testData, Base64.encodeBase64String(importedKey.getEncoded()));
        String decrypted = SM2Utils.decrypt(encrypted, privateKeyBase64);
        Assert.assertEquals("加解密后应该与原文一致", testData, decrypted);

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
        byte[] derBytes = SM22Utils.exportPrivateKeyToDER(privateKeyBase64);

        // 从 DER 导入
        ECPrivateKey importedKey = SM22Utils.importPrivateKeyFromDER(derBytes);
        Assert.assertNotNull("导入的私钥不应为空", importedKey);

        // 验证导入的密钥可以正常使用
        String encrypted = SM2Utils.encrypt(testData, publicKeyBase64);
        String decrypted = SM2Utils.decrypt(encrypted, Base64.encodeBase64String(importedKey.getEncoded()));
        Assert.assertEquals("加解密后应该与原文一致", testData, decrypted);

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
        String pemString = SM22Utils.exportPublicKeyToPEM(publicKeyBase64);

        // 从 PEM 导入
        ECPublicKey importedKey = SM22Utils.importPublicKeyFromPEM(pemString);
        Assert.assertNotNull("导入的公钥不应为空", importedKey);

        // 验证导入的密钥可以正常使用
        String encrypted = SM2Utils.encrypt(testData, Base64.encodeBase64String(importedKey.getEncoded()));
        String decrypted = SM2Utils.decrypt(encrypted, privateKeyBase64);
        Assert.assertEquals("加解密后应该与原文一致", testData, decrypted);

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
        String pemString = SM22Utils.exportPrivateKeyToPEM(privateKeyBase64);

        // 从 PEM 导入
        ECPrivateKey importedKey = SM22Utils.importPrivateKeyFromPEM(pemString);
        Assert.assertNotNull("导入的私钥不应为空", importedKey);

        // 验证导入的密钥可以正常使用
        String encrypted = SM2Utils.encrypt(testData, publicKeyBase64);
        String decrypted = SM2Utils.decrypt(encrypted, Base64.encodeBase64String(importedKey.getEncoded()));
        Assert.assertEquals("加解密后应该与原文一致", testData, decrypted);

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

        String filePath = "test_sm2_public.der";

        try {
            // 导出到文件
            SM22Utils.exportPublicKeyToDERFile(publicKeyBase64, filePath);
            System.out.println("已导出公钥到文件: " + filePath);

            // 从文件导入
            ECPublicKey importedKey = SM22Utils.importPublicKeyFromDERFile(filePath);
            Assert.assertNotNull("导入的公钥不应为空", importedKey);

            // 验证
            byte[] original = SM22Utils.exportPublicKeyToDER(publicKeyBase64);
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

        String filePath = "test_sm2_private.der";

        try {
            // 导出到文件
            SM22Utils.exportPrivateKeyToDERFile(privateKeyBase64, filePath);
            System.out.println("已导出私钥到文件: " + filePath);

            // 从文件导入
            ECPrivateKey importedKey = SM22Utils.importPrivateKeyFromDERFile(filePath);
            Assert.assertNotNull("导入的私钥不应为空", importedKey);

            // 验证
            byte[] original = SM22Utils.exportPrivateKeyToDER(privateKeyBase64);
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

        String filePath = "test_sm2_public.pem";

        try {
            // 导出到文件
            SM22Utils.exportPublicKeyToPEMFile(publicKeyBase64, filePath);
            System.out.println("已导出公钥到文件: " + filePath);

            // 从文件导入
            ECPublicKey importedKey = SM22Utils.importPublicKeyFromPEMFile(filePath);
            Assert.assertNotNull("导入的公钥不应为空", importedKey);

            // 验证
            byte[] original = SM22Utils.exportPublicKeyToDER(publicKeyBase64);
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

        String filePath = "test_sm2_private.pem";

        try {
            // 导出到文件
            SM22Utils.exportPrivateKeyToPEMFile(privateKeyBase64, filePath);
            System.out.println("已导出私钥到文件: " + filePath);

            // 从文件导入
            ECPrivateKey importedKey = SM22Utils.importPrivateKeyFromPEMFile(filePath);
            Assert.assertNotNull("导入的私钥不应为空", importedKey);

            // 验证
            byte[] original = SM22Utils.exportPrivateKeyToDER(privateKeyBase64);
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
        byte[] publicDER1 = SM22Utils.exportPublicKeyToDER(publicKeyBase64);
        String publicPEM = SM22Utils.exportPublicKeyToPEM(publicKeyBase64);
        ECPublicKey publicKey = SM22Utils.importPublicKeyFromPEM(publicPEM);
        byte[] publicDER2 = publicKey.getEncoded();
        Assert.assertTrue("公钥 DER-PEM-DER 转换应保持一致", Arrays.equals(publicDER1, publicDER2));
        System.out.println("✓ 公钥 DER-PEM 互转测试通过");

        // 私钥：DER -> PEM -> DER
        byte[] privateDER1 = SM22Utils.exportPrivateKeyToDER(privateKeyBase64);
        String privatePEM = SM22Utils.exportPrivateKeyToPEM(privateKeyBase64);
        ECPrivateKey privateKey = SM22Utils.importPrivateKeyFromPEM(privatePEM);
        byte[] privateDER2 = privateKey.getEncoded();
        Assert.assertTrue("私钥 DER-PEM-DER 转换应保持一致", Arrays.equals(privateDER1, privateDER2));
        System.out.println("✓ 私钥 DER-PEM 互转测试通过\n");
    }

    /**
     * 综合测试
     */
    @Test
    public void testAll() {
        System.out.println("\n========== SM22Utils 综合测试 ==========\n");

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

        System.out.println("========== 所有测试通过 ==========\n");
    }

}
