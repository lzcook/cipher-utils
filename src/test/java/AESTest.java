import com.lzc.lib.util.cipher.constant.Algorithm;
import com.lzc.lib.util.cipher.constant.Mode;
import com.lzc.lib.util.cipher.constant.Padding;
import com.lzc.lib.util.cipher.exception.CipherException;
import com.lzc.lib.util.cipher.symmetry.AESUtils;
import org.apache.commons.codec.binary.Base64;
import org.junit.Assert;
import org.junit.Test;

import java.time.Clock;
import java.util.Arrays;

/**
 * AESUtils 测试类
 * 包含基本加解密、CTR模式、GCM模式、IV生成等功能测试
 *
 * @author lzc
 * 2019/2/19 21:29
 */
public class AESTest {

    private String content = "0123456789ABCDEF";
    private String key = "hello world, hi!";
    // 16字节随机数据的 Base64 编码 (0102030405060708090A0B0C0D0E0F10 的 Base64)
    private String iv = "AQIDBAUGBwgJCgsMDQ4PEA==";

    // CTR/GCM 模式测试数据
    private String ctrGcmContent = "Hello, AES-CTR and AES-GCM encryption!";
    private String key16 = "1234567890123456"; // 16字节密钥
    private String key24 = "123456789012345678901234"; // 24字节密钥
    private String key32 = "12345678901234567890123456789012"; // 32字节密钥
    // 16字节随机数据的 Base64 编码
    private String iv16 = "AQIDBAUGBwgJCgsMDQ4PEA==";
    // 12字节随机数据的 Base64 编码
    private String iv12 = "AQIDBAUGBwgJCgsM";
    private String aad = "Additional Authentication Data";

    @Test
    public void getAlgorithm() {
        System.out.println(Algorithm.getAlgorithm(Algorithm.AES, Mode.CBC, Padding.PKCS7Padding));
        System.out.println(Algorithm.getAlgorithm(Algorithm.AES, Mode.ECB, Padding.NoPadding));
    }

    @Test
    public void generateKey() {
        System.out.println(Arrays.toString(AESUtils.generateKey(256)));
    }

    @Test
    public void testTime() {
        long millis = Clock.systemUTC().millis();
        for (int i = 0; i < 10000; i++) {
            test();
        }
        System.out.println(Clock.systemUTC().millis() - millis);
    }

    @Test
    public void tes1t() {
        // ECB 模式不使用 NoPadding，改为使用 PKCS7Padding
        System.out.println(AESUtils.encryptECB("testtesttesttestt", key));
    }

    @Test
    public void test() {
        // 使用明确的 CBC 方法
        System.out.println(AESUtils.encryptCBC(content, key, iv));
        System.out.println(AESUtils.decryptCBC(AESUtils.encryptCBC(content, key, iv), key, iv));

        System.out.println(AESUtils.encryptCBC(content, key, iv));
        System.out.println(AESUtils.decryptCBC(AESUtils.encryptCBC(content, key, iv), key, iv));

        // ECB 模式测试（已废弃，但保留用于兼容性测试）
        System.out.println(AESUtils.encryptECB(content, key));
        System.out.println(AESUtils.decryptECB(AESUtils.encryptECB(content, key), key));

        System.out.println(AESUtils.encryptECB(content, key));
        System.out.println(AESUtils.decryptECB(AESUtils.encryptECB(content, key), key));

        // CBC 模式测试
        System.out.println(AESUtils.encryptCBC(content, key, iv));
        System.out.println(AESUtils.decryptCBC(AESUtils.encryptCBC(content, key, iv), key, iv));

        System.out.println(AESUtils.encryptCBC(content, key, iv));
        System.out.println(AESUtils.decryptCBC(AESUtils.encryptCBC(content, key, iv), key, iv));

        // 使用已废弃的通用方法测试 CFB 模式（保留用于兼容性）
        System.out.println(AESUtils.encrypt(content, key, iv, Mode.CFB, Padding.PKCS7Padding));
        System.out.println(AESUtils.decrypt(AESUtils.encrypt(content, key, iv, Mode.CFB, Padding.PKCS7Padding), key, iv, Mode.CFB, Padding.PKCS7Padding));

        // CTR 模式测试（使用明确的方法）
        System.out.println(AESUtils.encryptCTR(content, key, iv));
        System.out.println(AESUtils.decryptCTR(AESUtils.encryptCTR(content, key, iv), key, iv));

        // 使用已废弃的通用方法测试 OFB 模式（保留用于兼容性）
        System.out.println(AESUtils.encrypt(content, key, iv, Mode.OFB, Padding.PKCS7Padding));
        System.out.println(AESUtils.decrypt(AESUtils.encrypt(content, key, iv, Mode.OFB, Padding.PKCS7Padding), key, iv, Mode.OFB, Padding.PKCS7Padding));

    }

    // ========== 以下是 CTR 和 GCM 模式测试 ==========

    /**
     * 测试 AES-CTR 模式加解密（16字节密钥）
     */
    @Test
    public void testCTREncryptDecrypt16() {
        System.out.println("=== 测试 AES-CTR 模式（16字节密钥）===");

        // 测试字符串加解密
        String encrypted = AESUtils.encryptCTR(ctrGcmContent, key16, iv16);
        System.out.println("原文: " + ctrGcmContent);
        System.out.println("密文: " + encrypted);

        String decrypted = AESUtils.decryptCTR(encrypted, key16, iv16);
        System.out.println("解密: " + decrypted);

        Assert.assertEquals("CTR 解密后应该与原文一致", ctrGcmContent, decrypted);

        // 测试字节数组加解密
        byte[] encryptedBytes = AESUtils.encryptCTR(ctrGcmContent.getBytes(), key16.getBytes(), iv16);
        byte[] decryptedBytes = AESUtils.decryptCTR(encryptedBytes, key16.getBytes(), iv16);
        Assert.assertEquals("CTR 字节数组解密后应该与原文一致", ctrGcmContent, new String(decryptedBytes));

        System.out.println("✓ AES-CTR 16字节密钥测试通过\n");
    }

    /**
     * 测试 AES-CTR 模式加解密（24字节密钥）
     */
    @Test
    public void testCTREncryptDecrypt24() {
        System.out.println("=== 测试 AES-CTR 模式（24字节密钥）===");

        String encrypted = AESUtils.encryptCTR(ctrGcmContent, key24, iv16);
        System.out.println("原文: " + ctrGcmContent);
        System.out.println("密文: " + encrypted);

        String decrypted = AESUtils.decryptCTR(encrypted, key24, iv16);
        System.out.println("解密: " + decrypted);

        Assert.assertEquals("CTR 解密后应该与原文一致", ctrGcmContent, decrypted);
        System.out.println("✓ AES-CTR 24字节密钥测试通过\n");
    }

    /**
     * 测试 AES-CTR 模式加解密（32字节密钥）
     */
    @Test
    public void testCTREncryptDecrypt32() {
        System.out.println("=== 测试 AES-CTR 模式（32字节密钥）===");

        String encrypted = AESUtils.encryptCTR(ctrGcmContent, key32, iv16);
        System.out.println("原文: " + ctrGcmContent);
        System.out.println("密文: " + encrypted);

        String decrypted = AESUtils.decryptCTR(encrypted, key32, iv16);
        System.out.println("解密: " + decrypted);

        Assert.assertEquals("CTR 解密后应该与原文一致", ctrGcmContent, decrypted);
        System.out.println("✓ AES-CTR 32字节密钥测试通过\n");
    }

    /**
     * 测试 AES-CTR 模式使用 NoPadding
     */
    @Test
    public void testCTRWithNoPadding() {
        System.out.println("=== 测试 AES-CTR 模式（NoPadding）===");

        String encrypted = AESUtils.encryptCTR(ctrGcmContent, key16, iv16, Padding.NoPadding);
        System.out.println("原文: " + ctrGcmContent);
        System.out.println("密文: " + encrypted);

        String decrypted = AESUtils.decryptCTR(encrypted, key16, iv16, Padding.NoPadding);
        System.out.println("解密: " + decrypted);

        Assert.assertEquals("CTR NoPadding 解密后应该与原文一致", ctrGcmContent, decrypted);
        System.out.println("✓ AES-CTR NoPadding 测试通过\n");
    }

    /**
     * 测试 AES-GCM 模式加解密（不带 AAD）
     */
    @Test
    public void testGCMEncryptDecrypt() {
        System.out.println("=== 测试 AES-GCM 模式（不带 AAD）===");

        // 测试字符串加解密
        String encrypted = AESUtils.encryptGCM(ctrGcmContent, key16, iv12);
        System.out.println("原文: " + ctrGcmContent);
        System.out.println("密文: " + encrypted);

        String decrypted = AESUtils.decryptGCM(encrypted, key16, iv12);
        System.out.println("解密: " + decrypted);

        Assert.assertEquals("GCM 解密后应该与原文一致", ctrGcmContent, decrypted);

        // 测试字节数组加解密
        byte[] encryptedBytes = AESUtils.encryptGCM(ctrGcmContent.getBytes(), key16.getBytes(), iv12);
        byte[] decryptedBytes = AESUtils.decryptGCM(encryptedBytes, key16.getBytes(), iv12);
        Assert.assertEquals("GCM 字节数组解密后应该与原文一致", ctrGcmContent, new String(decryptedBytes));

        System.out.println("✓ AES-GCM 不带 AAD 测试通过\n");
    }

    /**
     * 测试 AES-GCM 模式加解密（带 AAD）
     */
    @Test
    public void testGCMEncryptDecryptWithAAD() {
        System.out.println("=== 测试 AES-GCM 模式（带 AAD）===");

        String encrypted = AESUtils.encryptGCM(ctrGcmContent, key16, iv12, aad);
        System.out.println("原文: " + ctrGcmContent);
        System.out.println("AAD: " + aad);
        System.out.println("密文: " + encrypted);

        String decrypted = AESUtils.decryptGCM(encrypted, key16, iv12, aad);
        System.out.println("解密: " + decrypted);

        Assert.assertEquals("GCM 带 AAD 解密后应该与原文一致", ctrGcmContent, decrypted);
        System.out.println("✓ AES-GCM 带 AAD 测试通过\n");
    }

    /**
     * 测试 AES-GCM 模式使用不同密钥长度
     */
    @Test
    public void testGCMWithDifferentKeyLengths() {
        System.out.println("=== 测试 AES-GCM 模式（不同密钥长度）===");

        // 16字节密钥
        String encrypted16 = AESUtils.encryptGCM(ctrGcmContent, key16, iv12);
        String decrypted16 = AESUtils.decryptGCM(encrypted16, key16, iv12);
        Assert.assertEquals("GCM 16字节密钥解密应该成功", ctrGcmContent, decrypted16);
        System.out.println("✓ 16字节密钥测试通过");

        // 24字节密钥
        String encrypted24 = AESUtils.encryptGCM(ctrGcmContent, key24, iv12);
        String decrypted24 = AESUtils.decryptGCM(encrypted24, key24, iv12);
        Assert.assertEquals("GCM 24字节密钥解密应该成功", ctrGcmContent, decrypted24);
        System.out.println("✓ 24字节密钥测试通过");

        // 32字节密钥
        String encrypted32 = AESUtils.encryptGCM(ctrGcmContent, key32, iv12);
        String decrypted32 = AESUtils.decryptGCM(encrypted32, key32, iv12);
        Assert.assertEquals("GCM 32字节密钥解密应该成功", ctrGcmContent, decrypted32);
        System.out.println("✓ 32字节密钥测试通过\n");
    }

    /**
     * 测试 AES-GCM 认证失败（AAD 不匹配）
     */
    @Test(expected = CipherException.class)
    public void testGCMAuthenticationFailureWithWrongAAD() {
        System.out.println("=== 测试 AES-GCM 认证失败（AAD 不匹配）===");

        String encrypted = AESUtils.encryptGCM(ctrGcmContent, key16, iv12, aad);
        System.out.println("使用正确 AAD 加密成功");

        // 使用错误的 AAD 解密，应该抛出异常
        System.out.println("尝试使用错误 AAD 解密...");
        AESUtils.decryptGCM(encrypted, key16, iv12, "wrong aad");
    }

    /**
     * 测试 AES-GCM 认证失败（密文被篡改）
     */
    @Test(expected = CipherException.class)
    public void testGCMAuthenticationFailureWithTamperedData() {
        System.out.println("=== 测试 AES-GCM 认证失败（密文被篡改）===");

        String encrypted = AESUtils.encryptGCM(ctrGcmContent, key16, iv12);
        System.out.println("加密成功: " + encrypted);

        // 篡改密文
        String tampered = encrypted.substring(0, encrypted.length() - 4) + "XXXX";
        System.out.println("篡改密文: " + tampered);

        // 解密被篡改的密文，应该抛出异常
        System.out.println("尝试解密被篡改的密文...");
        AESUtils.decryptGCM(tampered, key16, iv12);
    }

    /**
     * 测试无效密钥长度
     */
    @Test(expected = CipherException.class)
    public void testInvalidKeyLength() {
        System.out.println("=== 测试无效密钥长度 ===");
        String invalidKey = "short";
        AESUtils.encryptCTR(ctrGcmContent, invalidKey, iv16);
    }

    /**
     * 测试 CTR 模式无效 IV 长度
     */
    @Test(expected = CipherException.class)
    public void testCTRInvalidIVLength() {
        System.out.println("=== 测试 CTR 模式无效 IV 长度 ===");
        String invalidIV = "short";
        AESUtils.encryptCTR(ctrGcmContent, key16, invalidIV);
    }

    /**
     * 测试空数据加解密
     */
    @Test
    public void testEmptyData() {
        System.out.println("=== 测试空数据加解密 ===");

        // CTR 模式
        String ctrResult = AESUtils.encryptCTR(null, key16, iv16);
        Assert.assertNull("CTR 加密 null 应返回 null", ctrResult);

        String ctrResult2 = AESUtils.encryptCTR("", key16, iv16);
        String ctrDecrypted = AESUtils.decryptCTR(ctrResult2, key16, iv16);
        Assert.assertEquals("CTR 加密空字符串应该能正常解密", "", ctrDecrypted);

        // GCM 模式
        String gcmResult = AESUtils.encryptGCM(null, key16, iv12);
        Assert.assertNull("GCM 加密 null 应返回 null", gcmResult);

        String gcmResult2 = AESUtils.encryptGCM("", key16, iv12);
        String gcmDecrypted = AESUtils.decryptGCM(gcmResult2, key16, iv12);
        Assert.assertEquals("GCM 加密空字符串应该能正常解密", "", gcmDecrypted);

        System.out.println("✓ 空数据测试通过\n");
    }

    /**
     * 测试大数据量加解密
     */
    @Test
    public void testLargeData() {
        System.out.println("=== 测试大数据量加解密 ===");

        // 生成 1MB 数据
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 1024 * 64; i++) {
            sb.append("0123456789ABCDEF");
        }
        String largeContent = sb.toString();

        System.out.println("数据大小: " + largeContent.length() + " 字节");

        // CTR 模式
        long startTime = System.currentTimeMillis();
        String ctrEncrypted = AESUtils.encryptCTR(largeContent, key16, iv16);
        long encryptTime = System.currentTimeMillis() - startTime;
        System.out.println("CTR 加密耗时: " + encryptTime + " ms");

        startTime = System.currentTimeMillis();
        String ctrDecrypted = AESUtils.decryptCTR(ctrEncrypted, key16, iv16);
        long decryptTime = System.currentTimeMillis() - startTime;
        System.out.println("CTR 解密耗时: " + decryptTime + " ms");

        Assert.assertEquals("CTR 大数据解密应该成功", largeContent, ctrDecrypted);

        // GCM 模式
        startTime = System.currentTimeMillis();
        String gcmEncrypted = AESUtils.encryptGCM(largeContent, key16, iv12);
        encryptTime = System.currentTimeMillis() - startTime;
        System.out.println("GCM 加密耗时: " + encryptTime + " ms");

        startTime = System.currentTimeMillis();
        String gcmDecrypted = AESUtils.decryptGCM(gcmEncrypted, key16, iv12);
        decryptTime = System.currentTimeMillis() - startTime;
        System.out.println("GCM 解密耗时: " + decryptTime + " ms");

        Assert.assertEquals("GCM 大数据解密应该成功", largeContent, gcmDecrypted);

        System.out.println("✓ 大数据测试通过\n");
    }

    /**
     * 测试 CTR 模式 IV 生成
     */
    @Test
    public void testGenerateIVForCTR() {
        System.out.println("=== 测试 CTR 模式 IV 生成 ===");

        // 生成 CTR 模式的 IV
        String iv = AESUtils.generateIVForCTR();
        System.out.println("生成的 IV (Base64): " + iv);
        byte[] ivBytes = Base64.decodeBase64(iv);
        System.out.println("IV 解码后长度: " + ivBytes.length + " 字节");

        // 验证 IV 解码后长度
        Assert.assertEquals("CTR IV 解码后长度应该是 16 字节", 16, ivBytes.length);

        // 验证生成的 IV 可用于加解密
        String encrypted = AESUtils.encryptCTR(ctrGcmContent, key16, iv);
        String decrypted = AESUtils.decryptCTR(encrypted, key16, iv);
        Assert.assertEquals("使用生成的 IV 加解密应该成功", ctrGcmContent, decrypted);

        System.out.println("✓ CTR IV 生成测试通过\n");
    }

    /**
     * 测试 GCM 模式 IV 生成
     */
    @Test
    public void testGenerateIVForGCM() {
        System.out.println("=== 测试 GCM 模式 IV 生成 ===");

        // 生成 GCM 模式的 IV（12字节，推荐）
        String iv = AESUtils.generateIVForGCM();
        System.out.println("生成的 IV (Base64): " + iv);
        byte[] ivBytes = Base64.decodeBase64(iv);
        System.out.println("IV 解码后长度: " + ivBytes.length + " 字节");

        // 验证 IV 解码后长度
        Assert.assertEquals("GCM IV 解码后长度应该是 12 字节", 12, ivBytes.length);

        // 验证生成的 IV 可用于加解密
        String encrypted = AESUtils.encryptGCM(ctrGcmContent, key16, iv);
        String decrypted = AESUtils.decryptGCM(encrypted, key16, iv);
        Assert.assertEquals("使用生成的 IV 加解密应该成功", ctrGcmContent, decrypted);

        System.out.println("✓ GCM IV 生成测试通过\n");
    }

    /**
     * 测试自定义长度 GCM IV 生成
     */
    @Test
    public void testGenerateIVForGCMWithCustomLength() {
        System.out.println("=== 测试自定义长度 GCM IV 生成 ===");

        // 生成不同长度的 IV
        int[] lengths = {8, 12, 16, 32};
        for (int length : lengths) {
            String iv = AESUtils.generateIVForGCM(length);
            System.out.println("生成 " + length + " 字节的 IV (Base64): " + iv);
            byte[] ivBytes = Base64.decodeBase64(iv);
            Assert.assertEquals("IV 解码后长度应该是 " + length + " 字节", length, ivBytes.length);

            // 验证可用于加解密
            String encrypted = AESUtils.encryptGCM(ctrGcmContent, key16, iv);
            String decrypted = AESUtils.decryptGCM(encrypted, key16, iv);
            Assert.assertEquals("使用自定义长度 IV 加解密应该成功", ctrGcmContent, decrypted);
        }

        System.out.println("✓ 自定义长度 GCM IV 生成测试通过\n");
    }

    /**
     * 测试 IV 字节数组生成
     */
    @Test
    public void testGenerateRandomIVBytes() {
        System.out.println("=== 测试 IV 字节数组生成 ===");

        // 生成不同长度的字节数组 IV
        int[] lengths = {12, 16, 32};
        for (int length : lengths) {
            byte[] ivBytes = AESUtils.generateRandomIVBytes(length);
            System.out.println("生成 " + length + " 字节的 IV 字节数组");
            Assert.assertEquals("IV 字节数组长度应该是 " + length, length, ivBytes.length);
            Assert.assertNotNull("IV 字节数组不应该为 null", ivBytes);
        }

        System.out.println("✓ IV 字节数组生成测试通过\n");
    }

    /**
     * 测试 IV 唯一性（随机性）
     */
    @Test
    public void testIVUniqueness() {
        System.out.println("=== 测试 IV 唯一性 ===");

        // 生成多个 IV，验证它们都不相同
        int count = 100;
        java.util.Set<String> ivSet = new java.util.HashSet<>();

        for (int i = 0; i < count; i++) {
            String iv = AESUtils.generateIVForGCM();
            ivSet.add(iv);
        }

        // 验证所有生成的 IV 都不相同
        Assert.assertEquals("生成的 " + count + " 个 IV 应该都不相同", count, ivSet.size());
        System.out.println("✓ 生成 " + count + " 个 IV，全部唯一");

        System.out.println("✓ IV 唯一性测试通过\n");
    }

    /**
     * 测试无效 IV 长度
     */
    @Test(expected = CipherException.class)
    public void testInvalidIVLength() {
        System.out.println("=== 测试无效 IV 长度 ===");
        // 尝试生成长度为 0 的 IV，应该抛出异常
        AESUtils.generateIVForGCM(0);
    }

    /**
     * 测试负数 IV 长度
     */
    @Test(expected = CipherException.class)
    public void testNegativeIVLength() {
        System.out.println("=== 测试负数 IV 长度 ===");
        // 尝试生成负数长度的 IV，应该抛出异常
        AESUtils.generateRandomIVBytes(-1);
    }

    /**
     * 测试使用随机生成的 IV 进行完整加解密流程
     */
    @Test
    public void testEncryptDecryptWithGeneratedIV() {
        System.out.println("=== 测试使用随机生成的 IV 进行加解密 ===");

        // CTR 模式
        String ctrIV = AESUtils.generateIVForCTR();
        String ctrEncrypted = AESUtils.encryptCTR(ctrGcmContent, key16, ctrIV);
        String ctrDecrypted = AESUtils.decryptCTR(ctrEncrypted, key16, ctrIV);
        Assert.assertEquals("CTR 模式使用生成的 IV 加解密应该成功", ctrGcmContent, ctrDecrypted);
        System.out.println("✓ CTR 模式测试通过");

        // GCM 模式
        String gcmIV = AESUtils.generateIVForGCM();
        String gcmEncrypted = AESUtils.encryptGCM(ctrGcmContent, key16, gcmIV);
        String gcmDecrypted = AESUtils.decryptGCM(gcmEncrypted, key16, gcmIV);
        Assert.assertEquals("GCM 模式使用生成的 IV 加解密应该成功", ctrGcmContent, gcmDecrypted);
        System.out.println("✓ GCM 模式测试通过");

        // GCM 模式带 AAD
        String gcmIVWithAAD = AESUtils.generateIVForGCM();
        String gcmEncryptedWithAAD = AESUtils.encryptGCM(ctrGcmContent, key16, gcmIVWithAAD, aad);
        String gcmDecryptedWithAAD = AESUtils.decryptGCM(gcmEncryptedWithAAD, key16, gcmIVWithAAD, aad);
        Assert.assertEquals("GCM 模式带 AAD 使用生成的 IV 加解密应该成功", ctrGcmContent, gcmDecryptedWithAAD);
        System.out.println("✓ GCM 模式带 AAD 测试通过");

        System.out.println("✓ 使用随机生成的 IV 进行加解密测试通过\n");
    }

    /**
     * 测试 AES-CBC 模式加解密
     */
    @Test
    public void testCBCEncryptDecrypt() {
        System.out.println("=== 测试 AES-CBC 模式 ===");

        // 测试字符串加解密
        String encrypted = AESUtils.encryptCBC(ctrGcmContent, key16, iv16);
        System.out.println("原文: " + ctrGcmContent);
        System.out.println("密文: " + encrypted);

        String decrypted = AESUtils.decryptCBC(encrypted, key16, iv16);
        System.out.println("解密: " + decrypted);

        Assert.assertEquals("CBC 解密后应该与原文一致", ctrGcmContent, decrypted);

        // 测试字节数组加解密
        byte[] encryptedBytes = AESUtils.encryptCBC(ctrGcmContent.getBytes(), key16.getBytes(), iv16);
        byte[] decryptedBytes = AESUtils.decryptCBC(encryptedBytes, key16.getBytes(), iv16);
        Assert.assertEquals("CBC 字节数组解密后应该与原文一致", ctrGcmContent, new String(decryptedBytes));

        System.out.println("✓ AES-CBC 模式测试通过\n");
    }

    /**
     * 测试 AES-ECB 模式加解密（已废弃，仅用于兼容性测试）
     */
    @Test
    public void testECBEncryptDecrypt() {
        System.out.println("=== 测试 AES-ECB 模式（已废弃，仅兼容性测试）===");

        // 测试字符串加解密
        String encrypted = AESUtils.encryptECB(ctrGcmContent, key16);
        System.out.println("原文: " + ctrGcmContent);
        System.out.println("密文: " + encrypted);

        String decrypted = AESUtils.decryptECB(encrypted, key16);
        System.out.println("解密: " + decrypted);

        Assert.assertEquals("ECB 解密后应该与原文一致", ctrGcmContent, decrypted);

        // 测试字节数组加解密
        byte[] encryptedBytes = AESUtils.encryptECB(ctrGcmContent.getBytes(), key16.getBytes());
        byte[] decryptedBytes = AESUtils.decryptECB(encryptedBytes, key16.getBytes());
        Assert.assertEquals("ECB 字节数组解密后应该与原文一致", ctrGcmContent, new String(decryptedBytes));

        System.out.println("✓ AES-ECB 模式测试通过（警告：ECB 模式不安全）\n");
    }

    /**
     * 测试 CBC 模式 IV 生成
     */
    @Test
    public void testGenerateIVForCBC() {
        System.out.println("=== 测试 CBC 模式 IV 生成 ===");

        // 生成 CBC 模式的 IV
        String iv = AESUtils.generateIVForCBC();
        System.out.println("生成的 IV (Base64): " + iv);
        byte[] ivBytes = Base64.decodeBase64(iv);
        System.out.println("IV 解码后长度: " + ivBytes.length + " 字节");

        // 验证 IV 解码后长度
        Assert.assertEquals("CBC IV 解码后长度应该是 16 字节", 16, ivBytes.length);

        // 验证生成的 IV 可用于加解密
        String encrypted = AESUtils.encryptCBC(ctrGcmContent, key16, iv);
        String decrypted = AESUtils.decryptCBC(encrypted, key16, iv);
        Assert.assertEquals("使用生成的 IV 加解密应该成功", ctrGcmContent, decrypted);

        System.out.println("✓ CBC IV 生成测试通过\n");
    }

    /**
     * 综合测试
     */
    @Test
    public void testAll() {
        System.out.println("\n========== AESUtils 综合测试 ==========\n");

        // CBC 模式测试
        testCBCEncryptDecrypt();
        testGenerateIVForCBC();

        // ECB 模式测试（已废弃）
        testECBEncryptDecrypt();

        // CTR 模式测试
        testCTREncryptDecrypt16();
        testCTREncryptDecrypt24();
        testCTREncryptDecrypt32();
        testCTRWithNoPadding();
        testGenerateIVForCTR();

        // GCM 模式测试
        testGCMEncryptDecrypt();
        testGCMEncryptDecryptWithAAD();
        testGCMWithDifferentKeyLengths();
        testGenerateIVForGCM();
        testGenerateIVForGCMWithCustomLength();

        // 通用测试
        testEmptyData();
        testLargeData();
        testGenerateRandomIVBytes();
        testIVUniqueness();
        testEncryptDecryptWithGeneratedIV();

        System.out.println("========== 所有测试通过 ==========\n");
    }

}
