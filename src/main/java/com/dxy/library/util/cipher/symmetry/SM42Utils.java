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
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Security;

/**
 * SM4 扩展工具类，支持 CTR 和 GCM 模式
 * SM4: 中国国家密码标准，密钥长度 128 位，块长度 128 位
 * CTR: 计数器模式，可并行加解密，不需要填充
 * GCM: 伽罗瓦计数器模式，认证加密，提供数据完整性和机密性保障
 *
 * @author duanxinyuan
 * 2025/11/03
 */
public class SM42Utils {

    static {
        // 导入 BouncyCastle Provider
        Security.addProvider(new BouncyCastleProvider());
    }

    // GCM 模式的认证标签长度（位）
    private static final int GCM_TAG_LENGTH = 128;

    // IV 长度常量
    private static final int IV_LENGTH_CTR = 16;  // CTR 模式 IV 长度（字节）
    private static final int IV_LENGTH_GCM = 12;  // GCM 模式 IV 长度（字节，推荐）

    /**
     * SM4-CTR 加密（使用 PKCS5Padding）
     * @param data 明文（Base64编码）
     * @param key 密钥（Base64编码），长度必须是16位
     * @param iv 初始化向量，长度必须为16位
     * @return 密文（Base64编码）
     */
    public static String encryptCTR(String data, String key, String iv) {
        return encryptCTR(data, key, iv, Padding.PKCS5Padding);
    }

    /**
     * SM4-CTR 加密
     * @param data 明文
     * @param key 密钥，长度必须是16位
     * @param iv 初始化向量，长度必须为16位
     * @return 密文
     */
    public static byte[] encryptCTR(byte[] data, byte[] key, String iv) {
        return encryptCTR(data, key, iv, Padding.PKCS5Padding);
    }

    /**
     * SM4-CTR 加密
     * @param data 明文（Base64编码）
     * @param key 密钥（Base64编码），长度必须是16位
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
     * SM4-CTR 加密
     * @param data 明文
     * @param key 密钥，长度必须是16位
     * @param iv 初始化向量，长度必须为16位
     * @param padding 填充方式
     * @return 密文
     */
    public static byte[] encryptCTR(byte[] data, byte[] key, String iv, Padding padding) {
        checkKey(key);
        checkIv(iv);
        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, Algorithm.SM4.getAlgorithm());
            String algorithm = Algorithm.getAlgorithm(Algorithm.SM4, Mode.CTR, padding);
            Cipher cipher = Cipher.getInstance(algorithm);

            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes(StandardCharsets.ISO_8859_1));
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new CipherException("SM4-CTR encrypt error", e);
        }
    }

    /**
     * SM4-CTR 解密（使用 PKCS5Padding）
     * @param data 密文（Base64编码）
     * @param key 密钥（Base64编码），长度必须是16位
     * @param iv 初始化向量，长度必须为16位
     * @return 明文
     */
    public static String decryptCTR(String data, String key, String iv) {
        return decryptCTR(data, key, iv, Padding.PKCS5Padding);
    }

    /**
     * SM4-CTR 解密
     * @param data 密文
     * @param key 密钥，长度必须是16位
     * @param iv 初始化向量，长度必须为16位
     * @return 明文
     */
    public static byte[] decryptCTR(byte[] data, byte[] key, String iv) {
        return decryptCTR(data, key, iv, Padding.PKCS5Padding);
    }

    /**
     * SM4-CTR 解密
     * @param data 密文（Base64编码）
     * @param key 密钥（Base64编码），长度必须是16位
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
     * SM4-CTR 解密
     * @param data 密文
     * @param key 密钥，长度必须是16位
     * @param iv 初始化向量，长度必须为16位
     * @param padding 填充方式
     * @return 明文
     */
    public static byte[] decryptCTR(byte[] data, byte[] key, String iv, Padding padding) {
        checkKey(key);
        checkIv(iv);
        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, Algorithm.SM4.getAlgorithm());
            String algorithm = Algorithm.getAlgorithm(Algorithm.SM4, Mode.CTR, padding);
            Cipher cipher = Cipher.getInstance(algorithm);

            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes(StandardCharsets.ISO_8859_1));
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);

            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new CipherException("SM4-CTR decrypt error", e);
        }
    }

    /**
     * SM4-GCM 加密（推荐使用，提供认证加密）
     * @param data 明文（Base64编码）
     * @param key 密钥（Base64编码），长度必须是16位
     * @param iv 初始化向量，推荐12字节
     * @return 密文（Base64编码）
     */
    public static String encryptGCM(String data, String key, String iv) {
        return encryptGCM(data, key, iv, null);
    }

    /**
     * SM4-GCM 加密
     * @param data 明文
     * @param key 密钥，长度必须是16位
     * @param iv 初始化向量，推荐12字节
     * @return 密文
     */
    public static byte[] encryptGCM(byte[] data, byte[] key, String iv) {
        return encryptGCM(data, key, iv, null);
    }

    /**
     * SM4-GCM 加密（带附加认证数据）
     * @param data 明文（Base64编码）
     * @param key 密钥（Base64编码），长度必须是16位
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
     * SM4-GCM 加密（带附加认证数据）
     * @param data 明文
     * @param key 密钥，长度必须是16位
     * @param iv 初始化向量，推荐12字节
     * @param aad 附加认证数据（Additional Authenticated Data），可选
     * @return 密文（包含认证标签）
     */
    public static byte[] encryptGCM(byte[] data, byte[] key, String iv, byte[] aad) {
        checkKey(key);
        checkIvGCM(iv);
        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, Algorithm.SM4.getAlgorithm());
            String algorithm = Algorithm.getAlgorithm(Algorithm.SM4, Mode.GCM, Padding.NoPadding);
            Cipher cipher = Cipher.getInstance(algorithm);

            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv.getBytes(StandardCharsets.ISO_8859_1));
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, gcmParameterSpec);

            // 如果有附加认证数据，添加到加密过程中
            if (aad != null && aad.length > 0) {
                cipher.updateAAD(aad);
            }

            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new CipherException("SM4-GCM encrypt error", e);
        }
    }

    /**
     * SM4-GCM 解密
     * @param data 密文（Base64编码）
     * @param key 密钥（Base64编码），长度必须是16位
     * @param iv 初始化向量，推荐12字节
     * @return 明文
     */
    public static String decryptGCM(String data, String key, String iv) {
        return decryptGCM(data, key, iv, null);
    }

    /**
     * SM4-GCM 解密
     * @param data 密文
     * @param key 密钥，长度必须是16位
     * @param iv 初始化向量，推荐12字节
     * @return 明文
     */
    public static byte[] decryptGCM(byte[] data, byte[] key, String iv) {
        return decryptGCM(data, key, iv, null);
    }

    /**
     * SM4-GCM 解密（带附加认证数据）
     * @param data 密文（Base64编码）
     * @param key 密钥（Base64编码），长度必须是16位
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
     * SM4-GCM 解密（带附加认证数据）
     * @param data 密文（包含认证标签）
     * @param key 密钥，长度必须是16位
     * @param iv 初始化向量，推荐12字节
     * @param aad 附加认证数据（Additional Authenticated Data），必须与加密时相同
     * @return 明文
     */
    public static byte[] decryptGCM(byte[] data, byte[] key, String iv, byte[] aad) {
        checkKey(key);
        checkIvGCM(iv);
        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, Algorithm.SM4.getAlgorithm());
            String algorithm = Algorithm.getAlgorithm(Algorithm.SM4, Mode.GCM, Padding.NoPadding);
            Cipher cipher = Cipher.getInstance(algorithm);

            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv.getBytes(StandardCharsets.ISO_8859_1));
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, gcmParameterSpec);

            // 如果有附加认证数据，添加到解密过程中
            if (aad != null && aad.length > 0) {
                cipher.updateAAD(aad);
            }

            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new CipherException("SM4-GCM decrypt error", e);
        }
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
     * 校验 SM4 密钥，长度必须是16位
     */
    private static void checkKey(byte[] key) {
        if (key == null) {
            throw new CipherException("SM4 key cannot be null");
        }
        if (key.length != 16) {
            throw new CipherException("SM4 key not 16 bytes long");
        }
    }

    /**
     * 校验 SM4 初始化向量（CTR 模式），长度必须是16位
     */
    private static void checkIv(String iv) {
        if (StringUtils.isEmpty(iv)) {
            throw new CipherException("SM4 IV cannot be empty");
        }
        if (iv.length() != 16) {
            throw new CipherException("SM4 IV not 16 bytes long for CTR mode");
        }
    }

    /**
     * 校验 SM4 初始化向量（GCM 模式），推荐12字节
     */
    private static void checkIvGCM(String iv) {
        if (StringUtils.isEmpty(iv)) {
            throw new CipherException("SM4 IV cannot be empty");
        }
        // GCM 模式推荐使用12字节的 IV，但也支持其他长度
        if (iv.length() < 1) {
            throw new CipherException("SM4 IV too short for GCM mode");
        }
    }

}
