package com.lzc.lib.util.cipher.symmetry;

import com.lzc.lib.util.cipher.constant.Algorithm;
import com.lzc.lib.util.cipher.constant.Mode;
import com.lzc.lib.util.cipher.constant.Padding;
import com.lzc.lib.util.cipher.exception.CipherException;
import com.lzc.lib.util.cipher.utils.RandomUtil;
import org.apache.commons.codec.binary.Base64;
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
 * AES对称加密工具类（高级加密标准）
 * 支持多种加密模式：GCM（推荐）、CBC、CTR、ECB（已弃用）
 * 默认使用CBC模式，密钥长度支持128/192/256位
 * 详细使用说明和安全建议请参考 README.md
 *
 * @author lzc
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
     * AES加密（推荐方式，使用AES/CBC/PKCS7Padding）
     * <p>这是最常用的便捷方法，使用安全的 CBC 模式和 PKCS7 填充</p>
     * <p>如需更高安全性，推荐使用 {@link #encryptGCM(String, String, String)} 方法</p>
     * @param data 明文（Base64编码）
     * @param key 密钥（Base64编码），长度必须是16或24或者32位
     * @param iv 偏移量，长度必须为16位，建议使用 {@link #generateIVForCBC()} 生成
     * @return 密文（Base64编码）
     */
    public static String encrypt(String data, String key, String iv) {
        return encrypt(data, key, iv, Mode.CBC, Padding.PKCS7Padding);
    }

    /**
     * AES加密（推荐方式，使用AES/CBC/PKCS7Padding）
     * <p>这是最常用的便捷方法，使用安全的 CBC 模式和 PKCS7 填充</p>
     * <p>如需更高安全性，推荐使用 {@link #encryptGCM(byte[], byte[], String)} 方法</p>
     * @param data 明文
     * @param key 密钥，长度必须是16或24或者32位
     * @param iv 偏移量，长度必须为16位，建议使用 {@link #generateIVForCBC()} 生成
     * @return 密文
     */
    public static byte[] encrypt(byte[] data, byte[] key, String iv) {
        return encrypt(data, key, iv, Mode.CBC, Padding.PKCS7Padding);
    }

    /**
     * AES加密（不带偏移量）
     * @param data 密文（Base64编码）
     * @param key 密钥（Base64编码），长度必须是16或24或者32位
     * @deprecated 请使用明确的模式方法，如 {@link #encryptGCM(String, String, String)}、{@link #encryptCBC(String, String, String)}、{@link #encryptCTR(String, String, String)} 或 {@link #encryptECB(String, String)}
     */
    @Deprecated
    public static String encrypt(String data, String key, Mode mode, Padding padding) {
        return encrypt(data, key, null, mode, padding);
    }

    /**
     * AES加密（不带偏移量）
     * @param data 密文
     * @param key 密钥，长度必须是16或24或者32位
     * @return 密文（Base64编码）
     * @deprecated 请使用明确的模式方法，如 {@link #encryptGCM(byte[], byte[], String)}、{@link #encryptCBC(byte[], byte[], String)}、{@link #encryptCTR(byte[], byte[], String)} 或 {@link #encryptECB(byte[], byte[])}
     */
    @Deprecated
    public static byte[] encrypt(byte[] data, byte[] key, Mode mode, Padding padding) {
        return encrypt(data, key, null, mode, padding);
    }

    /**
     * AES加密（通用方法，支持自定义模式和填充）
     * @param data 明文（Base64编码）
     * @param key 密钥（Base64编码），长度必须是16或24或者32位
     * @param iv 偏移量，长度必须为16位
     * @param mode 密码块工作模式
     * @param padding 填充方式
     * @return 密文（Base64编码）
     * @deprecated 请使用明确的模式方法，如 {@link #encryptGCM(String, String, String)}、{@link #encryptCBC(String, String, String)}、{@link #encryptCTR(String, String, String)} 或 {@link #encryptECB(String, String)}
     */
    @Deprecated
    public static String encrypt(String data, String key, String iv, Mode mode, Padding padding) {
        if (data == null || data.isEmpty()) {
            return null;
        }
        byte[] encrypt = encrypt(data.getBytes(), key.getBytes(), iv, mode, padding);
        return Base64.encodeBase64String(encrypt);
    }

    /**
     * AES加密（通用方法，支持自定义模式和填充）
     * @param data 明文
     * @param key 密钥，长度必须是16或24或者32位
     * @param iv 偏移量，长度必须为16位
     * @param mode 密码块工作模式
     * @param padding 填充方式
     * @return 密文
     * @deprecated 请使用明确的模式方法，如 {@link #encryptGCM(byte[], byte[], String)}、{@link #encryptCBC(byte[], byte[], String)}、{@link #encryptCTR(byte[], byte[], String)} 或 {@link #encryptECB(byte[], byte[])}
     */
    @Deprecated
    public static byte[] encrypt(byte[] data, byte[] key, String iv, Mode mode, Padding padding) {
        check(data, key, iv, mode, padding);
        try {
            SecretKeySpec secretKeySpec = getSecretKeySpec(key);
            String algorithm = Algorithm.getAlgorithm(Algorithm.AES, mode, padding);
            // 创建密码器
            Cipher cipher = Cipher.getInstance(algorithm);
            // 初始化
            if (iv != null && !iv.isEmpty()) {
                AlgorithmParameters parameters = AlgorithmParameters.getInstance(Algorithm.AES.getAlgorithm());
                // IV 使用 Base64 解码，保证跨语言兼容性
                parameters.init(new IvParameterSpec(Base64.decodeBase64(iv)));
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
     * AES解密（推荐方式，使用AES/CBC/PKCS7Padding）
     * <p>这是最常用的便捷方法，使用安全的 CBC 模式和 PKCS7 填充</p>
     * <p>如需更高安全性，推荐使用 {@link #decryptGCM(String, String, String)} 方法</p>
     * @param data 密文（Base64编码）
     * @param key 密钥（Base64编码），长度必须是16或24或者32位
     * @param iv 偏移量，长度必须为16位，必须与加密时使用的 IV 相同
     * @return 明文
     */
    public static String decrypt(String data, String key, String iv) {
        return decrypt(data, key, iv, Mode.CBC, Padding.PKCS7Padding);
    }

    /**
     * AES解密（推荐方式，使用AES/CBC/PKCS7Padding）
     * <p>这是最常用的便捷方法，使用安全的 CBC 模式和 PKCS7 填充</p>
     * <p>如需更高安全性，推荐使用 {@link #decryptGCM(byte[], byte[], String)} 方法</p>
     * @param data 密文
     * @param key 密钥，长度必须是16或24或者32位
     * @param iv 偏移量，长度必须为16位，必须与加密时使用的 IV 相同
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
     * @deprecated 请使用明确的模式方法，如 {@link #decryptGCM(String, String, String)}、{@link #decryptCBC(String, String, String)}、{@link #decryptCTR(String, String, String)} 或 {@link #decryptECB(String, String)}
     */
    @Deprecated
    public static String decrypt(String data, String key, Mode mode, Padding padding) {
        return decrypt(data, key, null, mode, padding);
    }

    /**
     * AES解密（不带偏移量）
     * @param data 密文
     * @param key 密钥，长度必须是16或24或者32位
     * @return 明文
     * @deprecated 请使用明确的模式方法，如 {@link #decryptGCM(byte[], byte[], String)}、{@link #decryptCBC(byte[], byte[], String)}、{@link #decryptCTR(byte[], byte[], String)} 或 {@link #decryptECB(byte[], byte[])}
     */
    @Deprecated
    public static byte[] decrypt(byte[] data, byte[] key, Mode mode, Padding padding) {
        return decrypt(data, key, null, mode, padding);
    }

    /**
     * AES解密（通用方法，支持自定义模式和填充）
     * @param data 密文（Base64编码）
     * @param key 密钥（Base64编码），长度必须是16或24或者32位
     * @param iv 偏移量，长度必须为16位
     * @param mode 密码块工作模式
     * @param padding 填充方式
     * @return 明文
     * @deprecated 请使用明确的模式方法，如 {@link #decryptGCM(String, String, String)}、{@link #decryptCBC(String, String, String)}、{@link #decryptCTR(String, String, String)} 或 {@link #decryptECB(String, String)}
     */
    @Deprecated
    public static String decrypt(String data, String key, String iv, Mode mode, Padding padding) {
        if (data == null || data.isEmpty()) {
            return null;
        }
        byte[] decrypt = decrypt(Base64.decodeBase64(data), key.getBytes(), iv, mode, padding);
        return new String(decrypt);
    }

    /**
     * AES解密（通用方法，支持自定义模式和填充）
     * @param data 密文
     * @param key 密钥，长度必须是16或24或者32位
     * @param iv 偏移量，长度必须为16位
     * @param mode 密码块工作模式
     * @param padding 填充方式
     * @return 明文
     * @deprecated 请使用明确的模式方法，如 {@link #decryptGCM(byte[], byte[], String)}、{@link #decryptCBC(byte[], byte[], String)}、{@link #decryptCTR(byte[], byte[], String)} 或 {@link #decryptECB(byte[], byte[])}
     */
    @Deprecated
    public static byte[] decrypt(byte[] data, byte[] key, String iv, Mode mode, Padding padding) {
        check(data, key, iv, mode, padding);
        try {
            SecretKeySpec secretKeySpec = getSecretKeySpec(key);
            String algorithm = Algorithm.getAlgorithm(Algorithm.AES, mode, padding);
            // 创建密码器
            Cipher cipher = Cipher.getInstance(algorithm);
            // 初始化
            if (iv != null && !iv.isEmpty()) {
                AlgorithmParameters parameters = AlgorithmParameters.getInstance(Algorithm.AES.getAlgorithm());
                // IV 使用 Base64 解码，保证跨语言兼容性
                parameters.init(new IvParameterSpec(Base64.decodeBase64(iv)));
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
        if (iv != null && !iv.isEmpty()) {
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
        // ECB 模式不安全，但允许使用（仅用于兼容旧系统）
        if (mode == Mode.ECB) {
            System.err.println("WARNING: ECB mode is not secure! Use only for compatibility with legacy systems. Consider using GCM, CTR, or CBC mode instead.");
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
     * 校验AES偏移量，Base64编码后解码必须是16字节
     */
    private static void checkIv(String iv) {
        byte[] ivBytes = Base64.decodeBase64(iv);
        if (ivBytes.length != 16) {
            throw new CipherException("AES iv not 16 bytes long (decoded from Base64)");
        }
    }

    // ==================== CTR模式加密解密 ====================

    /**
     * AES-CTR 加密（推荐使用，流式加密模式）
     * <p>CTR 模式将块密码转换为流密码，不需要填充，使用 NoPadding</p>
     * @param data 明文（Base64编码）
     * @param key 密钥（Base64编码），长度必须是16或24或32位
     * @param iv 初始化向量，长度必须为16位
     * @return 密文（Base64编码）
     */
    public static String encryptCTR(String data, String key, String iv) {
        return encryptCTR(data, key, iv, Padding.NoPadding);
    }

    /**
     * AES-CTR 加密（推荐使用，流式加密模式）
     * <p>CTR 模式将块密码转换为流密码，不需要填充，使用 NoPadding</p>
     * @param data 明文
     * @param key 密钥，长度必须是16或24或32位
     * @param iv 初始化向量，长度必须为16位
     * @return 密文
     */
    public static byte[] encryptCTR(byte[] data, byte[] key, String iv) {
        return encryptCTR(data, key, iv, Padding.NoPadding);
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

            // IV 使用 Base64 解码，保证跨语言兼容性
            IvParameterSpec ivParameterSpec = new IvParameterSpec(Base64.decodeBase64(iv));
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new CipherException("AES-CTR encrypt error", e);
        }
    }

    /**
     * AES-CTR 解密（推荐使用，流式加密模式）
     * <p>CTR 模式将块密码转换为流密码，不需要填充，使用 NoPadding</p>
     * @param data 密文（Base64编码）
     * @param key 密钥（Base64编码），长度必须是16或24或32位
     * @param iv 初始化向量，长度必须为16位
     * @return 明文
     */
    public static String decryptCTR(String data, String key, String iv) {
        return decryptCTR(data, key, iv, Padding.NoPadding);
    }

    /**
     * AES-CTR 解密（推荐使用，流式加密模式）
     * <p>CTR 模式将块密码转换为流密码，不需要填充，使用 NoPadding</p>
     * @param data 密文
     * @param key 密钥，长度必须是16或24或32位
     * @param iv 初始化向量，长度必须为16位
     * @return 明文
     */
    public static byte[] decryptCTR(byte[] data, byte[] key, String iv) {
        return decryptCTR(data, key, iv, Padding.NoPadding);
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

            // IV 使用 Base64 解码，保证跨语言兼容性
            IvParameterSpec ivParameterSpec = new IvParameterSpec(Base64.decodeBase64(iv));
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);

            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new CipherException("AES-CTR decrypt error", e);
        }
    }

    // ==================== CBC模式加密解密 ====================

    /**
     * AES-CBC 加密（推荐使用，传统块加密模式）
     * <p>使用 AES/CBC/PKCS7Padding，必须提供随机 IV</p>
     * @param data 明文（Base64编码）
     * @param key 密钥（Base64编码），长度必须是16或24或32位
     * @param iv 初始化向量，长度必须为16位，必须使用随机 IV
     * @return 密文（Base64编码）
     */
    public static String encryptCBC(String data, String key, String iv) {
        return encrypt(data, key, iv, Mode.CBC, Padding.PKCS7Padding);
    }

    /**
     * AES-CBC 加密（推荐使用，传统块加密模式）
     * <p>使用 AES/CBC/PKCS7Padding，必须提供随机 IV</p>
     * @param data 明文
     * @param key 密钥，长度必须是16或24或32位
     * @param iv 初始化向量，长度必须为16位，必须使用随机 IV
     * @return 密文
     */
    public static byte[] encryptCBC(byte[] data, byte[] key, String iv) {
        return encrypt(data, key, iv, Mode.CBC, Padding.PKCS7Padding);
    }

    /**
     * AES-CBC 解密（推荐使用，传统块加密模式）
     * <p>使用 AES/CBC/PKCS7Padding</p>
     * @param data 密文（Base64编码）
     * @param key 密钥（Base64编码），长度必须是16或24或32位
     * @param iv 初始化向量，长度必须为16位，必须与加密时使用的 IV 相同
     * @return 明文
     */
    public static String decryptCBC(String data, String key, String iv) {
        return decrypt(data, key, iv, Mode.CBC, Padding.PKCS7Padding);
    }

    /**
     * AES-CBC 解密（推荐使用，传统块加密模式）
     * <p>使用 AES/CBC/PKCS7Padding</p>
     * @param data 密文
     * @param key 密钥，长度必须是16或24或32位
     * @param iv 初始化向量，长度必须为16位，必须与加密时使用的 IV 相同
     * @return 明文
     */
    public static byte[] decryptCBC(byte[] data, byte[] key, String iv) {
        return decrypt(data, key, iv, Mode.CBC, Padding.PKCS7Padding);
    }

    // ==================== ECB模式加密解密（已弃用，仅用于兼容） ====================

    /**
     * AES-ECB 加密（不安全，已弃用）
     * <p><b>警告：ECB 模式不安全！仅用于兼容旧系统，不应用于生产环境。</b></p>
     * <p>ECB 模式对相同的明文块产生相同的密文块，容易泄露数据模式。</p>
     * <p>使用 AES/ECB/PKCS7Padding</p>
     * @param data 明文（Base64编码）
     * @param key 密钥（Base64编码），长度必须是16或24或32位
     * @return 密文（Base64编码）
     * @deprecated ECB 模式不安全，仅用于兼容旧系统。推荐使用 {@link #encryptGCM(String, String, String)} 或 {@link #encryptCBC(String, String, String)}
     */
    @Deprecated
    public static String encryptECB(String data, String key) {
        return encrypt(data, key, Mode.ECB, Padding.PKCS7Padding);
    }

    /**
     * AES-ECB 加密（不安全，已弃用）
     * <p><b>警告：ECB 模式不安全！仅用于兼容旧系统，不应用于生产环境。</b></p>
     * <p>ECB 模式对相同的明文块产生相同的密文块，容易泄露数据模式。</p>
     * <p>使用 AES/ECB/PKCS7Padding</p>
     * @param data 明文
     * @param key 密钥，长度必须是16或24或32位
     * @return 密文
     * @deprecated ECB 模式不安全，仅用于兼容旧系统。推荐使用 {@link #encryptGCM(byte[], byte[], String)} 或 {@link #encryptCBC(byte[], byte[], String)}
     */
    @Deprecated
    public static byte[] encryptECB(byte[] data, byte[] key) {
        return encrypt(data, key, Mode.ECB, Padding.PKCS7Padding);
    }

    /**
     * AES-ECB 解密（不安全，已弃用）
     * <p><b>警告：ECB 模式不安全！仅用于兼容旧系统，不应用于生产环境。</b></p>
     * <p>使用 AES/ECB/PKCS7Padding</p>
     * @param data 密文（Base64编码）
     * @param key 密钥（Base64编码），长度必须是16或24或32位
     * @return 明文
     * @deprecated ECB 模式不安全，仅用于兼容旧系统。推荐使用 {@link #decryptGCM(String, String, String)} 或 {@link #decryptCBC(String, String, String)}
     */
    @Deprecated
    public static String decryptECB(String data, String key) {
        return decrypt(data, key, Mode.ECB, Padding.PKCS7Padding);
    }

    /**
     * AES-ECB 解密（不安全，已弃用）
     * <p><b>警告：ECB 模式不安全！仅用于兼容旧系统，不应用于生产环境。</b></p>
     * <p>使用 AES/ECB/PKCS7Padding</p>
     * @param data 密文
     * @param key 密钥，长度必须是16或24或32位
     * @return 明文
     * @deprecated ECB 模式不安全，仅用于兼容旧系统。推荐使用 {@link #decryptGCM(byte[], byte[], String)} 或 {@link #decryptCBC(byte[], byte[], String)}
     */
    @Deprecated
    public static byte[] decryptECB(byte[] data, byte[] key) {
        return decrypt(data, key, Mode.ECB, Padding.PKCS7Padding);
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
        byte[] aadBytes = (aad == null || aad.isEmpty()) ? null : aad.getBytes(StandardCharsets.UTF_8);
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

            // IV 使用 Base64 解码，保证跨语言兼容性
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, Base64.decodeBase64(iv));
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
        byte[] aadBytes = (aad == null || aad.isEmpty()) ? null : aad.getBytes(StandardCharsets.UTF_8);
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

            // IV 使用 Base64 解码，保证跨语言兼容性
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, Base64.decodeBase64(iv));
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
     * 校验 AES 初始化向量（GCM 模式），推荐12字节（Base64 编码）
     */
    private static void checkIvGCM(String iv) {
        if (iv == null || iv.isEmpty()) {
            throw new CipherException("AES IV cannot be empty");
        }
        // 解码 Base64，检查实际字节长度
        byte[] ivBytes = Base64.decodeBase64(iv);
        // GCM 模式推荐使用12字节的 IV，但也支持其他长度
        if (ivBytes.length < 1) {
            throw new CipherException("AES IV too short for GCM mode");
        }
    }

}
