package com.dxy.library.util.cipher.symmetry;

import com.dxy.library.util.cipher.constant.Algorithm;
import com.dxy.library.util.cipher.constant.Mode;
import com.dxy.library.util.cipher.constant.Padding;
import com.dxy.library.util.cipher.exception.CipherException;
import com.dxy.library.util.cipher.utils.RandomUtil;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

/**
 * AES工具类
 * 高级加密标准(Advanced Encryption Standard)，密钥长可以选 128, 192, 256，块长128，用来替代原先的DES，速度快，安全
 * 优点：AES具有比DES更好的安全性、效率、灵活性，在软件及硬件上都能快速地加解密，相对来说较易于实作，且只需要很少的存储器。
 *
 * 功能包括：
 * - CBC/CFB/OFB/CTR模式的加密解密（推荐使用CBC或CTR模式）
 * - GCM模式的认证加密（推荐，提供数据完整性和机密性保障）
 * - 密钥生成
 * - IV生成
 *
 * 安全提示：
 * - 本工具类已移除ECB模式支持（ECB模式不安全，相同明文产生相同密文）
 * - 推荐使用GCM模式或CBC模式，必须使用随机IV
 *
 * @author duanxinyuan
 * 2019/2/15 18:41
 */
public class AESUtils {

    static {
        //导入Provider，BouncyCastle是一个开源的加解密解决方案，主页在http://www.bouncycastle.org/
        Security.addProvider(new BouncyCastleProvider());
    }

    // GCM 模式的认证标签长度（位）
    private static final int GCM_TAG_LENGTH = 128;

    // IV 长度常量
    private static final int IV_LENGTH_CBC = 16;  // CBC 模式 IV 长度（字节）
    private static final int IV_LENGTH_CTR = 16;  // CTR 模式 IV 长度（字节）
    private static final int IV_LENGTH_GCM = 12;  // GCM 模式 IV 长度（字节，推荐）

    /**
     * AES加密（推荐方式，使用AES/CBC/PKCS7Padding方式）
     * @param data 密文（Base64编码）
     * @param key 密钥（Base64编码），长度必须是16或24或者32位
     * @param iv 偏移量，长度必须为16位
     */
    public static String encrypt(String data, String key, String iv) {
        return encrypt(data, key, iv, Mode.CBC, Padding.PKCS7Padding);
    }

    /**
     * AES加密（最常用方式之一，使用AES/CBC/PKCS7Padding方式）
     * @param data 密文
     * @param key 密钥，长度必须是16或24或者32位
     * @param iv 偏移量，长度必须为16位
     */
    public static byte[] encrypt(byte[] data, byte[] key, String iv) {
        return encrypt(data, key, iv, Mode.CBC, Padding.PKCS7Padding);
    }

    /**
     * AES加密（不带偏移量）
     * @param data 密文（Base64编码）
     * @param key 密钥（Base64编码），长度必须是16或24或者32位
     */
    public static String encrypt(String data, String key, Mode mode, Padding padding) {
        return encrypt(data, key, null, mode, padding);
    }

    /**
     * AES加密（不带偏移量）
     * @param data 密文
     * @param key 密钥，长度必须是16或24或者32位
     * @return 密文（Base64编码）
     */
    public static byte[] encrypt(byte[] data, byte[] key, Mode mode, Padding padding) {
        return encrypt(data, key, null, mode, padding);
    }

    /**
     * AES加密
     * @param data 明文（Base64编码）
     * @param key 密钥（Base64编码），长度必须是16或24或者32位
     * @param iv 偏移量，长度必须为16位
     * @param mode 密码块工作模式
     * @param padding 填充方式
     * @return 密文（Base64编码）
     */
    public static String encrypt(String data, String key, String iv, Mode mode, Padding padding) {
        if (StringUtils.isEmpty(data)) {
            return null;
        }
        byte[] encrypt = encrypt(data.getBytes(), key.getBytes(), iv, mode, padding);
        return Base64.encodeBase64String(encrypt);
    }

    /**
     * AES加密
     * @param data 明文
     * @param key 密钥，长度必须是16或24或者32位
     * @param iv 偏移量，长度必须为16位
     * @param mode 密码块工作模式
     * @param padding 填充方式
     * @return 密文
     */
    public static byte[] encrypt(byte[] data, byte[] key, String iv, Mode mode, Padding padding) {
        check(data, key, iv, mode, padding);
        try {
            SecretKeySpec secretKeySpec = getSecretKeySpec(key);
            String algorithm = Algorithm.getAlgorithm(Algorithm.AES, mode, padding);
            // 创建密码器
            Cipher cipher = Cipher.getInstance(algorithm);
            // 初始化
            if (StringUtils.isNotEmpty(iv)) {
                AlgorithmParameters parameters = AlgorithmParameters.getInstance(Algorithm.AES.getAlgorithm());
                parameters.init(new IvParameterSpec(iv.getBytes(StandardCharsets.UTF_8)));
                cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, parameters);
            } else {
                cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
            }
            //加密
            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new CipherException("AES encrypt error", e);
        }
    }

    /**
     * AES解密（推荐方式，使用AES/CBC/PKCS7Padding方式）
     * @param data 密文（Base64编码）
     * @param key 密钥（Base64编码），长度必须是16或24或者32位
     * @param iv 偏移量，长度必须为16位
     * @return 明文
     */
    public static String decrypt(String data, String key, String iv) {
        return decrypt(data, key, iv, Mode.CBC, Padding.PKCS7Padding);
    }

    /**
     * AES解密（最常用方式之一，使用AES/CBC/PKCS7Padding方式）
     * @param data 密文
     * @param key 密钥，长度必须是16或24或者32位
     * @param iv 偏移量，长度必须为16位
     * @return 明文
     */
    public static byte[] decrypt(byte[] data, byte[] key, String iv) {
        return decrypt(data, key, iv, Mode.CBC, Padding.PKCS7Padding);
    }

    /**
     * AES解密（不带偏移量）
     * @param data 密文（Base64编码）
     * @param key 密钥（Base64编码），长度必须是16或24或者32位
     * @return 明文
     */
    public static String decrypt(String data, String key, Mode mode, Padding padding) {
        return decrypt(data, key, null, mode, padding);
    }

    /**
     * AES解密（不带偏移量）
     * @param data 密文
     * @param key 密钥，长度必须是16或24或者32位
     * @return 明文
     */
    public static byte[] decrypt(byte[] data, byte[] key, Mode mode, Padding padding) {
        return decrypt(data, key, null, mode, padding);
    }

    /**
     * AES解密
     * @param data 密文（Base64编码）
     * @param key 密钥（Base64编码），长度必须是16或24或者32位
     * @param iv 偏移量，长度必须为16位
     * @param mode 密码块工作模式
     * @param padding 填充方式
     * @return 明文
     */
    public static String decrypt(String data, String key, String iv, Mode mode, Padding padding) {
        if (StringUtils.isEmpty(data)) {
            return null;
        }
        byte[] decrypt = decrypt(Base64.decodeBase64(data), key.getBytes(), iv, mode, padding);
        return new String(decrypt);
    }

    /**
     * AES解密
     * @param data 密文
     * @param key 密钥，长度必须是16或24或者32位
     * @param iv 偏移量，长度必须为16位
     * @param mode 密码块工作模式
     * @param padding 填充方式
     * @return 明文
     */
    public static byte[] decrypt(byte[] data, byte[] key, String iv, Mode mode, Padding padding) {
        check(data, key, iv, mode, padding);
        try {
            SecretKeySpec secretKeySpec = getSecretKeySpec(key);
            String algorithm = Algorithm.getAlgorithm(Algorithm.AES, mode, padding);
            // 创建密码器
            Cipher cipher = Cipher.getInstance(algorithm);
            // 初始化
            if (StringUtils.isNotEmpty(iv)) {
                AlgorithmParameters parameters = AlgorithmParameters.getInstance(Algorithm.AES.getAlgorithm());
                parameters.init(new IvParameterSpec(iv.getBytes(StandardCharsets.UTF_8)));
                cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, parameters);
            } else {
                cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
            }
            //解密
            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new CipherException("AES decrypt error", e);
        }
    }

    /**
     * 生成AES的Key（128位）
     * @return 密钥
     */
    public static byte[] generateKey() {
        return generateKey(128);
    }

    /**
     * 生成AES的Key
     * @param length 密钥长度，可以选 128, 192, 256
     * @return 密钥
     */
    public static byte[] generateKey(int length) {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(Algorithm.AES.getAlgorithm());
            keyGenerator.init(length);
            SecretKey secretKey = keyGenerator.generateKey();
            return secretKey.getEncoded();
        } catch (NoSuchAlgorithmException e) {
            throw new CipherException("AES key generate error", e);
        }
    }

    private static SecretKeySpec getSecretKeySpec(byte[] key) {
        return new SecretKeySpec(key, Algorithm.AES.getAlgorithm());
    }

    private static void check(byte[] data, byte[] key, String iv, Mode mode, Padding padding) {
        checkKey(key);
        checkModeAndPadding(data, mode, padding);
        if (StringUtils.isNotEmpty(iv)) {
            checkIv(iv);
            if (mode == Mode.ECB) {
                throw new CipherException("AES ECB mode does not use an IV");
            }
        }
    }

    /**
     * 校验AES密码块工作模式和填充模式
     */
    private static void checkModeAndPadding(byte[] data, Mode mode, Padding padding) {
        if (mode == Mode.NONE) {
            throw new CipherException("invalid AES mode");
        }
        if (mode == Mode.ECB) {
            throw new CipherException("ECB mode is not secure and has been removed. Please use CBC, CTR, or GCM mode instead.");
        }
        if (padding == Padding.SSL3Padding || padding == Padding.PKCS1Padding) {
            throw new CipherException("invalid AES padding");
        }
        boolean is16NotSupport = padding == Padding.NoPadding && mode == Mode.CBC && data.length % 16 != 0;
        if (is16NotSupport) {
            throw new CipherException("data length must be multiple of 16 bytes on CBC/NoPadding mode");
        }
    }

    /**
     * 校验AES密钥，长度必须是16或24或者32位
     */
    private static void checkKey(byte[] key) {
        if (key == null) {
            throw new CipherException("AES key cannot be null");
        }
        if (key.length != 16 && key.length != 24 && key.length != 32) {
            throw new CipherException("AES key not 16/24/32 bytes long");
        }
    }

    /**
     * 校验AES偏移量，长度必须是16位
     */
    private static void checkIv(String iv) {
        if (iv.length() != 16) {
            throw new CipherException("AES iv not 16 bytes long");
        }
    }

    // ==================== CTR模式加密解密 ====================

    /**
     * AES-CTR 加密（使用 PKCS5Padding）
     * @param data 明文（Base64编码）
     * @param key 密钥（Base64编码），长度必须是16或24或32位
     * @param iv 初始化向量，长度必须为16位
     * @return 密文（Base64编码）
     */
    public static String encryptCTR(String data, String key, String iv) {
        return encryptCTR(data, key, iv, Padding.PKCS5Padding);
    }

    /**
     * AES-CTR 加密
     * @param data 明文
     * @param key 密钥，长度必须是16或24或32位
     * @param iv 初始化向量，长度必须为16位
     * @return 密文
     */
    public static byte[] encryptCTR(byte[] data, byte[] key, String iv) {
        return encryptCTR(data, key, iv, Padding.PKCS5Padding);
    }

    /**
     * AES-CTR 加密
     * @param data 明文（Base64编码）
     * @param key 密钥（Base64编码），长度必须是16或24或32位
     * @param iv 初始化向量，长度必须为16位
     * @param padding 填充方式
     * @return 密文（Base64编码）
     */
    public static String encryptCTR(String data, String key, String iv, Padding padding) {
        if (data == null) {
            return null;
        }
        byte[] encrypt = encryptCTR(data.getBytes(StandardCharsets.UTF_8), key.getBytes(StandardCharsets.UTF_8), iv, padding);
        return Base64.encodeBase64String(encrypt);
    }

    /**
     * AES-CTR 加密
     * @param data 明文
     * @param key 密钥，长度必须是16或24或32位
     * @param iv 初始化向量，长度必须为16位
     * @param padding 填充方式
     * @return 密文
     */
    public static byte[] encryptCTR(byte[] data, byte[] key, String iv, Padding padding) {
        checkKey(key);
        checkIv(iv);
        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, Algorithm.AES.getAlgorithm());
            String algorithm = Algorithm.getAlgorithm(Algorithm.AES, Mode.CTR, padding);
            Cipher cipher = Cipher.getInstance(algorithm);

            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes(StandardCharsets.ISO_8859_1));
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new CipherException("AES-CTR encrypt error", e);
        }
    }

    /**
     * AES-CTR 解密（使用 PKCS5Padding）
     * @param data 密文（Base64编码）
     * @param key 密钥（Base64编码），长度必须是16或24或32位
     * @param iv 初始化向量，长度必须为16位
     * @return 明文
     */
    public static String decryptCTR(String data, String key, String iv) {
        return decryptCTR(data, key, iv, Padding.PKCS5Padding);
    }

    /**
     * AES-CTR 解密
     * @param data 密文
     * @param key 密钥，长度必须是16或24或32位
     * @param iv 初始化向量，长度必须为16位
     * @return 明文
     */
    public static byte[] decryptCTR(byte[] data, byte[] key, String iv) {
        return decryptCTR(data, key, iv, Padding.PKCS5Padding);
    }

    /**
     * AES-CTR 解密
     * @param data 密文（Base64编码）
     * @param key 密钥（Base64编码），长度必须是16或24或32位
     * @param iv 初始化向量，长度必须为16位
     * @param padding 填充方式
     * @return 明文
     */
    public static String decryptCTR(String data, String key, String iv, Padding padding) {
        if (data == null) {
            return null;
        }
        byte[] decrypt = decryptCTR(Base64.decodeBase64(data), key.getBytes(StandardCharsets.UTF_8), iv, padding);
        return new String(decrypt, StandardCharsets.UTF_8);
    }

    /**
     * AES-CTR 解密
     * @param data 密文
     * @param key 密钥，长度必须是16或24或32位
     * @param iv 初始化向量，长度必须为16位
     * @param padding 填充方式
     * @return 明文
     */
    public static byte[] decryptCTR(byte[] data, byte[] key, String iv, Padding padding) {
        checkKey(key);
        checkIv(iv);
        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, Algorithm.AES.getAlgorithm());
            String algorithm = Algorithm.getAlgorithm(Algorithm.AES, Mode.CTR, padding);
            Cipher cipher = Cipher.getInstance(algorithm);

            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes(StandardCharsets.ISO_8859_1));
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);

            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new CipherException("AES-CTR decrypt error", e);
        }
    }

    // ==================== GCM模式加密解密 ====================

    /**
     * AES-GCM 加密（推荐使用，提供认证加密）
     * @param data 明文（Base64编码）
     * @param key 密钥（Base64编码），长度必须是16或24或32位
     * @param iv 初始化向量，推荐12字节
     * @return 密文（Base64编码）
     */
    public static String encryptGCM(String data, String key, String iv) {
        return encryptGCM(data, key, iv, null);
    }

    /**
     * AES-GCM 加密
     * @param data 明文
     * @param key 密钥，长度必须是16或24或32位
     * @param iv 初始化向量，推荐12字节
     * @return 密文
     */
    public static byte[] encryptGCM(byte[] data, byte[] key, String iv) {
        return encryptGCM(data, key, iv, null);
    }

    /**
     * AES-GCM 加密（带附加认证数据）
     * @param data 明文（Base64编码）
     * @param key 密钥（Base64编码），长度必须是16或24或32位
     * @param iv 初始化向量，推荐12字节
     * @param aad 附加认证数据（Additional Authenticated Data），可选
     * @return 密文（Base64编码）
     */
    public static String encryptGCM(String data, String key, String iv, String aad) {
        if (data == null) {
            return null;
        }
        byte[] aadBytes = StringUtils.isEmpty(aad) ? null : aad.getBytes(StandardCharsets.UTF_8);
        byte[] encrypt = encryptGCM(data.getBytes(StandardCharsets.UTF_8), key.getBytes(StandardCharsets.UTF_8), iv, aadBytes);
        return Base64.encodeBase64String(encrypt);
    }

    /**
     * AES-GCM 加密（带附加认证数据）
     * @param data 明文
     * @param key 密钥，长度必须是16或24或32位
     * @param iv 初始化向量，推荐12字节
     * @param aad 附加认证数据（Additional Authenticated Data），可选
     * @return 密文（包含认证标签）
     */
    public static byte[] encryptGCM(byte[] data, byte[] key, String iv, byte[] aad) {
        checkKey(key);
        checkIvGCM(iv);
        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, Algorithm.AES.getAlgorithm());
            String algorithm = Algorithm.getAlgorithm(Algorithm.AES, Mode.GCM, Padding.NoPadding);
            Cipher cipher = Cipher.getInstance(algorithm);

            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv.getBytes(StandardCharsets.ISO_8859_1));
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, gcmParameterSpec);

            // 如果有附加认证数据，添加到加密过程中
            if (aad != null && aad.length > 0) {
                cipher.updateAAD(aad);
            }

            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new CipherException("AES-GCM encrypt error", e);
        }
    }

    /**
     * AES-GCM 解密
     * @param data 密文（Base64编码）
     * @param key 密钥（Base64编码），长度必须是16或24或32位
     * @param iv 初始化向量，推荐12字节
     * @return 明文
     */
    public static String decryptGCM(String data, String key, String iv) {
        return decryptGCM(data, key, iv, null);
    }

    /**
     * AES-GCM 解密
     * @param data 密文
     * @param key 密钥，长度必须是16或24或32位
     * @param iv 初始化向量，推荐12字节
     * @return 明文
     */
    public static byte[] decryptGCM(byte[] data, byte[] key, String iv) {
        return decryptGCM(data, key, iv, null);
    }

    /**
     * AES-GCM 解密（带附加认证数据）
     * @param data 密文（Base64编码）
     * @param key 密钥（Base64编码），长度必须是16或24或32位
     * @param iv 初始化向量，推荐12字节
     * @param aad 附加认证数据（Additional Authenticated Data），必须与加密时相同
     * @return 明文
     */
    public static String decryptGCM(String data, String key, String iv, String aad) {
        if (data == null) {
            return null;
        }
        byte[] aadBytes = StringUtils.isEmpty(aad) ? null : aad.getBytes(StandardCharsets.UTF_8);
        byte[] decrypt = decryptGCM(Base64.decodeBase64(data), key.getBytes(StandardCharsets.UTF_8), iv, aadBytes);
        return new String(decrypt, StandardCharsets.UTF_8);
    }

    /**
     * AES-GCM 解密（带附加认证数据）
     * @param data 密文（包含认证标签）
     * @param key 密钥，长度必须是16或24或32位
     * @param iv 初始化向量，推荐12字节
     * @param aad 附加认证数据（Additional Authenticated Data），必须与加密时相同
     * @return 明文
     */
    public static byte[] decryptGCM(byte[] data, byte[] key, String iv, byte[] aad) {
        checkKey(key);
        checkIvGCM(iv);
        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, Algorithm.AES.getAlgorithm());
            String algorithm = Algorithm.getAlgorithm(Algorithm.AES, Mode.GCM, Padding.NoPadding);
            Cipher cipher = Cipher.getInstance(algorithm);

            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv.getBytes(StandardCharsets.ISO_8859_1));
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, gcmParameterSpec);

            // 如果有附加认证数据，添加到解密过程中
            if (aad != null && aad.length > 0) {
                cipher.updateAAD(aad);
            }

            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new CipherException("AES-GCM decrypt error", e);
        }
    }

    // ==================== IV生成工具方法 ====================

    /**
     * 生成用于 CBC 模式的随机 IV（16字节）
     * <p>使用密码学安全的随机数生成器（SecureRandom）</p>
     * @return 16字节的随机 IV 字符串
     */
    public static String generateIVForCBC() {
        return RandomUtil.generateRandomString(IV_LENGTH_CBC);
    }

    /**
     * 生成用于 CTR 模式的随机 IV（16字节）
     * <p>使用密码学安全的随机数生成器（SecureRandom）</p>
     * @return 16字节的随机 IV 字符串
     */
    public static String generateIVForCTR() {
        return RandomUtil.generateRandomString(IV_LENGTH_CTR);
    }

    /**
     * 生成用于 GCM 模式的随机 IV（12字节，推荐）
     * <p>使用密码学安全的随机数生成器（SecureRandom）</p>
     * @return 12字节的随机 IV 字符串
     */
    public static String generateIVForGCM() {
        return RandomUtil.generateRandomString(IV_LENGTH_GCM);
    }

    /**
     * 生成用于 GCM 模式的随机 IV（自定义长度）
     * <p>使用密码学安全的随机数生成器（SecureRandom）</p>
     * @param length IV 长度（字节），推荐 12 字节
     * @return 指定长度的随机 IV 字符串
     */
    public static String generateIVForGCM(int length) {
        return RandomUtil.generateRandomString(length);
    }

    /**
     * 生成随机 IV（字节数组）
     * <p>使用密码学安全的随机数生成器（SecureRandom）</p>
     * @param length IV 长度（字节）
     * @return 随机 IV 字节数组
     */
    public static byte[] generateRandomIVBytes(int length) {
        return RandomUtil.generateRandomBytes(length);
    }

    /**
     * 校验 AES 初始化向量（GCM 模式），推荐12字节
     */
    private static void checkIvGCM(String iv) {
        if (StringUtils.isEmpty(iv)) {
            throw new CipherException("AES IV cannot be empty");
        }
        // GCM 模式推荐使用12字节的 IV，但也支持其他长度
        if (iv.length() < 1) {
            throw new CipherException("AES IV too short for GCM mode");
        }
    }

}
