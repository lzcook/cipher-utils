package com.lzc.lib.util.cipher.utils;

import com.lzc.lib.util.cipher.exception.CipherException;
import org.junit.Assert;
import org.junit.Test;

import java.util.HashSet;
import java.util.Set;

/**
 * RandomUtil 测试类
 * 测试密码学安全的随机数生成功能
 *
 * @author lzc
 * 2025/11/03
 */
public class RandomUtilTest {

    /**
     * 测试生成随机字节数组
     */
    @Test
    public void testGenerateRandomBytes() {
        System.out.println("=== 测试生成随机字节数组 ===");

        int[] lengths = {1, 8, 16, 32, 64, 128};
        for (int length : lengths) {
            byte[] randomBytes = RandomUtil.generateRandomBytes(length);
            System.out.println("生成 " + length + " 字节的随机数组");
            Assert.assertNotNull("随机字节数组不应该为 null", randomBytes);
            Assert.assertEquals("随机字节数组长度应该是 " + length, length, randomBytes.length);
        }

        System.out.println("✓ 生成随机字节数组测试通过\n");
    }

    /**
     * 测试生成随机字符串
     */
    @Test
    public void testGenerateRandomString() {
        System.out.println("=== 测试生成随机字符串 ===");

        int[] lengths = {1, 8, 12, 16, 32, 64};
        for (int length : lengths) {
            String randomString = RandomUtil.generateRandomString(length);
            System.out.println("生成 " + length + " 字节的随机字符串");
            Assert.assertNotNull("随机字符串不应该为 null", randomString);
            Assert.assertEquals("随机字符串长度应该是 " + length, length, randomString.length());
        }

        System.out.println("✓ 生成随机字符串测试通过\n");
    }

    /**
     * 测试随机数唯一性
     */
    @Test
    public void testRandomBytesUniqueness() {
        System.out.println("=== 测试随机数唯一性 ===");

        int count = 1000;
        int length = 16;
        Set<String> randomSet = new HashSet<>();

        for (int i = 0; i < count; i++) {
            byte[] randomBytes = RandomUtil.generateRandomBytes(length);
            String hex = bytesToHex(randomBytes);
            randomSet.add(hex);
        }

        // 验证所有生成的随机数都不相同
        double uniqueRate = (double) randomSet.size() / count * 100;
        System.out.println("生成 " + count + " 个随机数，唯一数量: " + randomSet.size() + "，唯一率: " + String.format("%.2f", uniqueRate) + "%");
        Assert.assertTrue("随机数唯一率应该大于 99%", uniqueRate > 99.0);

        System.out.println("✓ 随机数唯一性测试通过\n");
    }

    /**
     * 测试随机字符串唯一性
     */
    @Test
    public void testRandomStringUniqueness() {
        System.out.println("=== 测试随机字符串唯一性 ===");

        int count = 1000;
        int length = 16;
        Set<String> randomSet = new HashSet<>();

        for (int i = 0; i < count; i++) {
            String randomString = RandomUtil.generateRandomString(length);
            randomSet.add(randomString);
        }

        // 验证所有生成的随机字符串都不相同
        double uniqueRate = (double) randomSet.size() / count * 100;
        System.out.println("生成 " + count + " 个随机字符串，唯一数量: " + randomSet.size() + "，唯一率: " + String.format("%.2f", uniqueRate) + "%");
        Assert.assertTrue("随机字符串唯一率应该大于 99%", uniqueRate > 99.0);

        System.out.println("✓ 随机字符串唯一性测试通过\n");
    }

    /**
     * 测试生成随机整数
     */
    @Test
    public void testGenerateRandomInt() {
        System.out.println("=== 测试生成随机整数 ===");

        int bound = 100;
        int count = 1000;
        int[] results = new int[count];

        for (int i = 0; i < count; i++) {
            int randomInt = RandomUtil.generateRandomInt(bound);
            results[i] = randomInt;
            Assert.assertTrue("随机整数应该在 [0, " + bound + ") 范围内", randomInt >= 0 && randomInt < bound);
        }

        // 验证随机性：检查是否有足够的分布
        Set<Integer> uniqueValues = new HashSet<>();
        for (int value : results) {
            uniqueValues.add(value);
        }

        System.out.println("生成 " + count + " 个随机整数（范围 [0, " + bound + ")），唯一值数量: " + uniqueValues.size());
        Assert.assertTrue("唯一值数量应该大于 " + (bound / 2), uniqueValues.size() > bound / 2);

        System.out.println("✓ 生成随机整数测试通过\n");
    }

    /**
     * 测试生成指定范围内的随机整数
     */
    @Test
    public void testGenerateRandomIntInRange() {
        System.out.println("=== 测试生成指定范围内的随机整数 ===");

        int min = 10;
        int max = 50;
        int count = 1000;

        for (int i = 0; i < count; i++) {
            int randomInt = RandomUtil.generateRandomIntInRange(min, max);
            Assert.assertTrue("随机整数应该在 [" + min + ", " + max + "] 范围内",
                randomInt >= min && randomInt <= max);
        }

        // 测试边界情况
        int sameValue = RandomUtil.generateRandomIntInRange(5, 5);
        Assert.assertEquals("当 min == max 时，返回值应该等于 min", 5, sameValue);

        System.out.println("✓ 生成指定范围内的随机整数测试通过\n");
    }

    /**
     * 测试生成随机长整数
     */
    @Test
    public void testGenerateRandomLong() {
        System.out.println("=== 测试生成随机长整数 ===");

        int count = 100;
        Set<Long> uniqueValues = new HashSet<>();

        for (int i = 0; i < count; i++) {
            long randomLong = RandomUtil.generateRandomLong();
            uniqueValues.add(randomLong);
        }

        System.out.println("生成 " + count + " 个随机长整数，唯一值数量: " + uniqueValues.size());
        Assert.assertTrue("唯一值数量应该大于 " + (count * 0.95), uniqueValues.size() > count * 0.95);

        System.out.println("✓ 生成随机长整数测试通过\n");
    }

    /**
     * 测试生成随机布尔值
     */
    @Test
    public void testGenerateRandomBoolean() {
        System.out.println("=== 测试生成随机布尔值 ===");

        int count = 1000;
        int trueCount = 0;
        int falseCount = 0;

        for (int i = 0; i < count; i++) {
            boolean randomBoolean = RandomUtil.generateRandomBoolean();
            if (randomBoolean) {
                trueCount++;
            } else {
                falseCount++;
            }
        }

        System.out.println("生成 " + count + " 个随机布尔值，true: " + trueCount + ", false: " + falseCount);

        // 验证分布应该大致均匀（允许 30%-70% 的范围）
        double trueRate = (double) trueCount / count;
        Assert.assertTrue("true 的比例应该在 30%-70% 之间", trueRate >= 0.3 && trueRate <= 0.7);

        System.out.println("✓ 生成随机布尔值测试通过\n");
    }

    /**
     * 测试生成随机十六进制字符串
     */
    @Test
    public void testGenerateRandomHex() {
        System.out.println("=== 测试生成随机十六进制字符串 ===");

        int[] byteLengths = {4, 8, 16, 32};
        for (int byteLength : byteLengths) {
            String randomHex = RandomUtil.generateRandomHex(byteLength);
            System.out.println("生成 " + byteLength + " 字节的十六进制字符串: " + randomHex);

            Assert.assertNotNull("十六进制字符串不应该为 null", randomHex);
            Assert.assertEquals("十六进制字符串长度应该是 " + (byteLength * 2),
                byteLength * 2, randomHex.length());

            // 验证是否只包含十六进制字符
            Assert.assertTrue("应该只包含十六进制字符", randomHex.matches("^[0-9a-f]+$"));
        }

        System.out.println("✓ 生成随机十六进制字符串测试通过\n");
    }

    /**
     * 测试随机十六进制字符串唯一性
     */
    @Test
    public void testRandomHexUniqueness() {
        System.out.println("=== 测试随机十六进制字符串唯一性 ===");

        int count = 1000;
        int byteLength = 16;
        Set<String> randomSet = new HashSet<>();

        for (int i = 0; i < count; i++) {
            String randomHex = RandomUtil.generateRandomHex(byteLength);
            randomSet.add(randomHex);
        }

        double uniqueRate = (double) randomSet.size() / count * 100;
        System.out.println("生成 " + count + " 个十六进制字符串，唯一数量: " + randomSet.size() +
            "，唯一率: " + String.format("%.2f", uniqueRate) + "%");
        Assert.assertTrue("十六进制字符串唯一率应该大于 99%", uniqueRate > 99.0);

        System.out.println("✓ 随机十六进制字符串唯一性测试通过\n");
    }

    /**
     * 测试无效参数：长度小于1
     */
    @Test(expected = CipherException.class)
    public void testInvalidLengthZero() {
        System.out.println("=== 测试无效长度 0 ===");
        RandomUtil.generateRandomBytes(0);
    }

    /**
     * 测试无效参数：负数长度
     */
    @Test(expected = CipherException.class)
    public void testInvalidLengthNegative() {
        System.out.println("=== 测试无效长度（负数）===");
        RandomUtil.generateRandomString(-1);
    }

    /**
     * 测试无效参数：bound 不是正数
     */
    @Test(expected = CipherException.class)
    public void testInvalidBoundZero() {
        System.out.println("=== 测试无效 bound 0 ===");
        RandomUtil.generateRandomInt(0);
    }

    /**
     * 测试无效参数：bound 为负数
     */
    @Test(expected = CipherException.class)
    public void testInvalidBoundNegative() {
        System.out.println("=== 测试无效 bound（负数）===");
        RandomUtil.generateRandomInt(-10);
    }

    /**
     * 测试无效参数：min 大于 max
     */
    @Test(expected = CipherException.class)
    public void testInvalidRange() {
        System.out.println("=== 测试无效范围（min > max）===");
        RandomUtil.generateRandomIntInRange(100, 10);
    }

    /**
     * 测试无效参数：十六进制长度为 0
     */
    @Test(expected = CipherException.class)
    public void testInvalidHexLengthZero() {
        System.out.println("=== 测试无效十六进制长度 0 ===");
        RandomUtil.generateRandomHex(0);
    }

    /**
     * 测试线程安全性
     */
    @Test
    public void testThreadSafety() throws InterruptedException {
        System.out.println("=== 测试线程安全性 ===");

        int threadCount = 10;
        int iterationsPerThread = 100;
        Set<String> allResults = new HashSet<>();

        Thread[] threads = new Thread[threadCount];
        for (int i = 0; i < threadCount; i++) {
            threads[i] = new Thread(() -> {
                for (int j = 0; j < iterationsPerThread; j++) {
                    String randomHex = RandomUtil.generateRandomHex(16);
                    synchronized (allResults) {
                        allResults.add(randomHex);
                    }
                }
            });
            threads[i].start();
        }

        // 等待所有线程完成
        for (Thread thread : threads) {
            thread.join();
        }

        int totalGenerated = threadCount * iterationsPerThread;
        double uniqueRate = (double) allResults.size() / totalGenerated * 100;
        System.out.println("多线程生成 " + totalGenerated + " 个随机值，唯一数量: " + allResults.size() +
            "，唯一率: " + String.format("%.2f", uniqueRate) + "%");
        Assert.assertTrue("多线程唯一率应该大于 99%", uniqueRate > 99.0);

        System.out.println("✓ 线程安全性测试通过\n");
    }

    /**
     * 测试 ThreadLocal 清理
     */
    @Test
    public void testThreadLocalCleanup() {
        System.out.println("=== 测试 ThreadLocal 清理 ===");

        // 使用随机数生成器
        String random1 = RandomUtil.generateRandomString(16);
        Assert.assertNotNull("生成的随机字符串不应该为 null", random1);

        // 清理 ThreadLocal
        RandomUtil.clearThreadLocalSecureRandom();

        // 清理后仍然可以正常使用
        String random2 = RandomUtil.generateRandomString(16);
        Assert.assertNotNull("清理后生成的随机字符串不应该为 null", random2);
        Assert.assertNotEquals("两次生成的随机字符串应该不同", random1, random2);

        System.out.println("✓ ThreadLocal 清理测试通过\n");
    }

    /**
     * 综合测试
     */
    @Test
    public void testAll() {
        System.out.println("\n========== RandomUtil 综合测试 ==========\n");

        testGenerateRandomBytes();
        testGenerateRandomString();
        testRandomBytesUniqueness();
        testRandomStringUniqueness();
        testGenerateRandomInt();
        testGenerateRandomIntInRange();
        testGenerateRandomLong();
        testGenerateRandomBoolean();
        testGenerateRandomHex();
        testRandomHexUniqueness();
        testThreadLocalCleanup();

        System.out.println("========== 所有测试通过 ==========\n");
    }

    // 辅助方法：字节数组转十六进制字符串
    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }
}
