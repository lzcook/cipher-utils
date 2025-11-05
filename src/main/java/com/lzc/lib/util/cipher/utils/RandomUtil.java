package com.lzc.lib.util.cipher.utils;

import com.lzc.lib.util.cipher.exception.CipherException;

import java.security.SecureRandom;
import java.util.Base64;

/**
 * 随机数生成工具类
 * 使用SecureRandom提供密码学安全的随机数生成
 * 使用ThreadLocal确保线程安全，详细技术说明请参考 README.md
 *
 * @author lzc
 * 2025/11/03
 */
public class RandomUtil {

    // 使用ThreadLocal确保线程安全，并复用SecureRandom实例
    private static final ThreadLocal<SecureRandom> SECURE_RANDOM = ThreadLocal.withInitial(SecureRandom::new);

    /**
     * 生成密码学安全的随机字节数组
     * <p>使用 SecureRandom 生成密码学安全的随机数</p>
     *
     * @param length 字节数组长度
     * @return 随机字节数组
     * @throws CipherException 如果长度小于1
     */
    public static byte[] generateRandomBytes(int length) {
        if (length < 1) {
            throw new CipherException("Random bytes length must be at least 1 byte");
        }

        SecureRandom secureRandom = SECURE_RANDOM.get();
        byte[] randomBytes = new byte[length];
        secureRandom.nextBytes(randomBytes);
        return randomBytes;
    }

    /**
     * 生成密码学安全的随机字符串（Base64 编码）
     * <p>使用 SecureRandom 生成随机字节，然后转换为 Base64 字符串</p>
     * <p>使用 Base64 编码，保证跨语言兼容性和安全传输</p>
     *
     * @param length 随机字节长度（注意：Base64 编码后的字符串长度约为 length * 4/3）
     * @return Base64 编码的随机字符串
     * @throws CipherException 如果长度小于1
     */
    public static String generateRandomString(int length) {
        if (length < 1) {
            throw new CipherException("Random string length must be at least 1 byte");
        }

        byte[] randomBytes = generateRandomBytes(length);
        // 使用 Base64 编码，保证跨语言兼容性
        return Base64.getEncoder().encodeToString(randomBytes);
    }

    /**
     * 生成密码学安全的随机整数
     *
     * @param bound 上界（不包含），必须为正数
     * @return 0（包含）到 bound（不包含）之间的随机整数
     * @throws CipherException 如果 bound 不是正数
     */
    public static int generateRandomInt(int bound) {
        if (bound <= 0) {
            throw new CipherException("Bound must be positive");
        }

        SecureRandom secureRandom = SECURE_RANDOM.get();
        return secureRandom.nextInt(bound);
    }

    /**
     * 生成密码学安全的随机长整数
     *
     * @return 随机长整数
     */
    public static long generateRandomLong() {
        SecureRandom secureRandom = SECURE_RANDOM.get();
        return secureRandom.nextLong();
    }

    /**
     * 生成密码学安全的随机布尔值
     *
     * @return 随机布尔值
     */
    public static boolean generateRandomBoolean() {
        SecureRandom secureRandom = SECURE_RANDOM.get();
        return secureRandom.nextBoolean();
    }

    /**
     * 生成指定长度的随机十六进制字符串
     *
     * @param byteLength 字节长度（生成的十六进制字符串长度为 byteLength * 2）
     * @return 随机十六进制字符串
     * @throws CipherException 如果长度小于1
     */
    public static String generateRandomHex(int byteLength) {
        if (byteLength < 1) {
            throw new CipherException("Random hex byte length must be at least 1 byte");
        }

        byte[] randomBytes = generateRandomBytes(byteLength);
        StringBuilder hexString = new StringBuilder(byteLength * 2);

        for (byte b : randomBytes) {
            hexString.append(String.format("%02x", b & 0xff));
        }

        return hexString.toString();
    }

    /**
     * 生成指定范围内的随机整数（包含上下界）
     *
     * @param min 最小值（包含）
     * @param max 最大值（包含）
     * @return min 到 max 之间的随机整数
     * @throws CipherException 如果 min 大于 max
     */
    public static int generateRandomIntInRange(int min, int max) {
        if (min > max) {
            throw new CipherException("Min must be less than or equal to max");
        }

        if (min == max) {
            return min;
        }

        SecureRandom secureRandom = SECURE_RANDOM.get();
        return secureRandom.nextInt(max - min + 1) + min;
    }

    /**
     * 清理当前线程的 SecureRandom 实例
     * <p>在线程结束前调用此方法可以释放资源</p>
     */
    public static void clearThreadLocalSecureRandom() {
        SECURE_RANDOM.remove();
    }
}
