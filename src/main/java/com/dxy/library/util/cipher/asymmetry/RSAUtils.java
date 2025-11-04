package com.dxy.library.util.cipher.asymmetry;

import com.dxy.library.util.cipher.constant.Algorithm;
import com.dxy.library.util.cipher.constant.Mode;
import com.dxy.library.util.cipher.constant.Padding;
import com.dxy.library.util.cipher.constant.RSASignType;
import com.dxy.library.util.cipher.exception.CipherException;
import com.dxy.library.util.cipher.pojo.RSAKeyPair;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * RSA工具类
 * 最典型的非对称加密算法，1978由Ron Rivest, AdiShamir 和Leonard Adleman三人发明
 * 同时有两把钥匙，公钥与私钥。支持数字签名，能用签名对传输过来的数据进行校验
 * 默认公钥X509格式，私钥PKCS8格式
 * RSA密文采用Base64方式编码
 *
 * 功能包括：
 * - 签名、验签
 * - 公钥加密、私钥解密
 * - 私钥加密、公钥解密
 * - 密钥导出导入（支持DER和PEM格式）
 * - 密钥文件读写
 *
 * @author duanxinyuan
 * 2017/9/6 19:20
 */
public class RSAUtils {

    static {
        //导入Provider，BouncyCastle是一个开源的加解密解决方案，主页在http://www.bouncycastle.org/
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * 公钥加密（最常用的模式，使用RSA/ECB/PKCS1Padding方式）
     * @param data 加密内容
     * @param publicKey 公钥（X509格式，经过base64编码）
     * @return 密文（Base64编码）
     */
    public static String encryptByPublicKey(String data, String publicKey) {
        return encryptByPublicKey(data, publicKey, Mode.ECB, Padding.PKCS1Padding);
    }

    /**
     * 公钥加密（最常用的模式，使用RSA/ECB/PKCS1Padding方式）
     * @param data 加密内容
     * @param publicKey 公钥（X509格式）
     * @return 密文
     */
    public static byte[] encryptByPublicKey(byte[] data, byte[] publicKey) {
        return encryptByPublicKey(data, publicKey, Mode.ECB, Padding.PKCS1Padding);
    }

    /**
     * 公钥加密
     * @param data 加密内容
     * @param publicKey 公钥（X509格式，经过base64编码）
     * @return 密文（Base64编码）
     */
    public static String encryptByPublicKey(String data, String publicKey, Mode mode, Padding padding) {
        return encrypt(data, getPublicKey(publicKey), mode, padding);
    }

    /**
     * 公钥加密
     * @param data 加密内容
     * @param publicKey 公钥（X509格式）
     * @return 密文
     */
    public static byte[] encryptByPublicKey(byte[] data, byte[] publicKey, Mode mode, Padding padding) {
        return encrypt(data, getPublicKey(publicKey), mode, padding);
    }

    /**
     * 私钥加密（最常用的模式，使用RSA/ECB/PKCS1Padding方式）
     * @param data 加密内容
     * @param privateKey 私钥
     * @return 密文（Base64编码）
     */
    public static String encryptByPrivateKey(String data, String privateKey) {
        return encryptByPrivateKey(data, privateKey, Mode.ECB, Padding.PKCS1Padding);
    }

    /**
     * 私钥加密（最常用的模式，使用RSA/ECB/PKCS1Padding方式）
     * @param data 加密内容
     * @param privateKey 私钥
     * @return 密文
     */
    public static byte[] encryptByPrivateKey(byte[] data, byte[] privateKey) {
        return encryptByPrivateKey(data, privateKey, Mode.ECB, Padding.PKCS1Padding);
    }

    /**
     * 私钥加密
     * @param data 加密内容
     * @param privateKey 私钥（PKCS8格式，经过base64编码）
     * @return 密文（Base64编码）
     */
    public static String encryptByPrivateKey(String data, String privateKey, Mode mode, Padding padding) {
        return encrypt(data, getPrivateKey(privateKey), mode, padding);
    }

    /**
     * 私钥加密
     * @param data 加密内容
     * @param privateKey 私钥（PKCS8格式）
     * @return 密文
     */
    public static byte[] encryptByPrivateKey(byte[] data, byte[] privateKey, Mode mode, Padding padding) {
        return encrypt(data, getPrivateKey(privateKey), mode, padding);
    }

    /**
     * 加密
     * @param data 加密内容
     * @param rsaKey 公钥/私钥
     * @return 密文（Base64编码）
     */
    public static String encrypt(String data, RSAKey rsaKey, Mode mode, Padding padding) {
        if (StringUtils.isEmpty(data)) {
            return null;
        }
        return Base64.encodeBase64String(encrypt(data.getBytes(), rsaKey, mode, padding));
    }

    /**
     * 加密
     * @param data 加密内容
     * @param rsaKey 公钥/私钥
     * @return 密文
     */
    public static byte[] encrypt(byte[] data, RSAKey rsaKey, Mode mode, Padding padding) {
        check(mode, padding);
        try {
            String algorithm = Algorithm.getAlgorithm(Algorithm.RSA, mode, padding);
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.ENCRYPT_MODE, (Key) rsaKey);

            // 加密时超过maxEncryptBlockSize字节就报错。为此采用分段加密的办法来加密
            int keyLength = rsaKey.getModulus().bitLength();
            //必须比 RSA密钥的模长(modulus) 短至少11个字节
            int blockSize = keyLength / 8 - 11;
            return segmentHandling(cipher, data, blockSize);
        } catch (Exception e) {
            throw new CipherException("RSA encrypt error", e);
        }
    }

    /**
     * 公钥解密
     * @param data 密文（Base64编码）
     * @param publicKey 公钥
     * @return 明文
     */
    public static String decryptByPublicKey(String data, String publicKey) {
        return decryptByPublicKey(data, publicKey, Mode.ECB, Padding.PKCS1Padding);
    }

    /**
     * 公钥解密
     * @param data 密文
     * @param publicKey 公钥
     * @return 明文
     */
    public static byte[] decryptByPublicKey(byte[] data, String publicKey) {
        return decryptByPublicKey(data, publicKey, Mode.ECB, Padding.PKCS1Padding);
    }

    /**
     * 公钥解密
     * @param data 密文（Base64编码）
     * @param publicKey 公钥
     * @return 明文
     */
    public static String decryptByPublicKey(String data, String publicKey, Mode mode, Padding padding) {
        try {
            RSAPublicKey rsaPublicKey = getPublicKey(publicKey);
            return decrypt(data, rsaPublicKey, mode, padding);
        } catch (Exception e) {
            throw new CipherException("RSA decrypt error", e);
        }
    }

    /**
     * 公钥解密
     * @param data 密文
     * @param publicKey 公钥
     * @return 明文
     */
    public static byte[] decryptByPublicKey(byte[] data, String publicKey, Mode mode, Padding padding) {
        RSAPublicKey rsaPublicKey = getPublicKey(publicKey);
        return decrypt(data, rsaPublicKey, mode, padding);
    }

    /**
     * 私钥解密
     * @param data 密文（Base64编码）
     * @param privateKey 私钥
     * @return 明文
     */
    public static String decryptByPrivateKey(String data, String privateKey) {
        return decryptByPrivateKey(data, privateKey, Mode.ECB, Padding.PKCS1Padding);
    }

    /**
     * 私钥解密
     * @param data 密文
     * @param privateKey 私钥
     * @return 明文
     */
    public static byte[] decryptByPrivateKey(byte[] data, String privateKey) {
        return decryptByPrivateKey(data, privateKey, Mode.ECB, Padding.PKCS1Padding);
    }

    /**
     * 私钥解密
     * @param data 密文（Base64编码）
     * @param privateKey 私钥
     * @return 明文
     */
    public static String decryptByPrivateKey(String data, String privateKey, Mode mode, Padding padding) {
        RSAPrivateKey rsaPrivateKey = getPrivateKey(privateKey);
        return decrypt(data, rsaPrivateKey, mode, padding);
    }

    /**
     * 私钥解密
     * @param data 密文
     * @param privateKey 私钥
     * @return 明文
     */
    public static byte[] decryptByPrivateKey(byte[] data, String privateKey, Mode mode, Padding padding) {
        RSAPrivateKey rsaPrivateKey = getPrivateKey(privateKey);
        return decrypt(data, rsaPrivateKey, mode, padding);
    }

    /**
     * 解密
     * @param data 密文（Base64编码）
     * @param rsaKey 公钥/私钥
     * @return 明文
     */
    public static String decrypt(String data, RSAKey rsaKey, Mode mode, Padding padding) {
        if (StringUtils.isEmpty(data)) {
            return null;
        }
        byte[] decrypt = decrypt(Base64.decodeBase64(data.getBytes()), rsaKey, mode, padding);
        return new String(decrypt);
    }

    /**
     * 解密
     * @param data 密文
     * @param rsaKey 公钥/私钥
     * @return 明文
     */
    public static byte[] decrypt(byte[] data, RSAKey rsaKey, Mode mode, Padding padding) {
        check(mode, padding);
        try {
            String algorithm = Algorithm.getAlgorithm(Algorithm.RSA, mode, padding);
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.DECRYPT_MODE, (Key) rsaKey);

            // 解密时超过maxDecryptBlockSize字节就报错。为此采用分段解密的办法来解密
            int keyLength = rsaKey.getModulus().bitLength();
            int blockSize = keyLength / 8;
            return segmentHandling(cipher, data, blockSize);
        } catch (Exception e) {
            throw new CipherException("RSA decrypt error", e);
        }
    }

    /**
     * 用私钥对信息生成数字签名
     * @param signType 签名类型
     * @param data 签名的数据
     * @param privateKey 私钥
     * @return 签名（base64编码）
     */
    public static String sign(RSASignType signType, String data, String privateKey) {
        return sign(signType, data.getBytes(), privateKey);
    }

    /**
     * 用私钥对信息生成数字签名
     * @param signType 签名类型
     * @param data 签名的数据
     * @param privateKey 私钥
     * @return 签名
     */
    public static String sign(RSASignType signType, byte[] data, String privateKey) {
        try {
            RSAPrivateKey rsaPrivateKey = getPrivateKey(privateKey);
            //用私钥对信息生成数字签名
            Signature signature = Signature.getInstance(signType.getType());
            signature.initSign(rsaPrivateKey);
            signature.update(data);
            return Base64.encodeBase64String(signature.sign());
        } catch (Exception e) {
            throw new CipherException("RSA sign error", e);
        }
    }

    /**
     * 用公钥校验数字签名
     * @param signType 签名类型
     * @param data 加密数据
     * @param publicKey 公钥
     * @param sign 签名（base64编码）
     * @return 验签结果，true表示验签通过
     */
    public static boolean verifySign(RSASignType signType, String data, String publicKey, String sign) {
        return verifySign(signType, data.getBytes(), publicKey, Base64.decodeBase64(sign));
    }

    /**
     * 用公钥校验数字签名
     * @param signType 签名类型
     * @param data 加密数据
     * @param publicKey 公钥
     * @param sign 签名
     * @return 验签结果，true表示验签通过
     */
    public static boolean verifySign(RSASignType signType, byte[] data, String publicKey, byte[] sign) {
        try {
            RSAPublicKey rsaPublicKey = getPublicKey(publicKey);
            Signature signature = Signature.getInstance(signType.getType());
            signature.initVerify(rsaPublicKey);
            signature.update(data);
            //验证签名是否正常
            return signature.verify(sign);
        } catch (Exception e) {
            throw new CipherException("RSA verify sign error", e);
        }
    }

    /**
     * 生成公钥和私钥
     */
    public static RSAKeyPair generateKey() {
        return generateKey(2048);
    }

    /**
     * 生成公钥和私钥
     */
    public static RSAKeyPair generateKey(int keysize) {
        SecureRandom sr = new SecureRandom();
        KeyPairGenerator kpg;
        try {
            kpg = KeyPairGenerator.getInstance(Algorithm.RSA.getAlgorithm());
        } catch (NoSuchAlgorithmException e) {
            throw new CipherException("RSA key generate error", e);
        }
        kpg.initialize(keysize, sr);
        //生成密匙对
        KeyPair keyPair = kpg.generateKeyPair();
        //得到公钥
        RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
        //得到私钥
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();

        RSAKeyPair rsaKeyPair = new RSAKeyPair();
        rsaKeyPair.setPublicKey(Base64.encodeBase64String(rsaPublicKey.getEncoded()));
        rsaKeyPair.setPrivateKey(Base64.encodeBase64String(rsaPrivateKey.getEncoded()));
        rsaKeyPair.setModules(rsaPublicKey.getModulus());
        return rsaKeyPair;
    }

    /**
     * 分段处理密文
     * @param cipher 加密算法
     * @param data 密文或者明文
     * @param blockSize 单次加解密最大长度，加解密时超过maxDecryptBlockSize字节就报错。为此采用分段解密的办法来解密
     */
    private static byte[] segmentHandling(Cipher cipher, byte[] data, int blockSize) throws IOException, IllegalBlockSizeException, BadPaddingException {
        byte[] result;
        try (ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream()) {
            int dataLength = data.length;
            for (int i = 0; i < dataLength; i += blockSize) {
                int contentLength = Math.min(dataLength - i, blockSize);
                byte[] doFinal = cipher.doFinal(data, i, contentLength);
                byteArrayOutputStream.write(doFinal);
            }
            result = byteArrayOutputStream.toByteArray();
        }
        return result;
    }

    /**
     * 获取公钥
     * @param publicKey 公钥（经过base64编码）
     * @return 公钥（X509格式）
     */
    public static RSAPublicKey getPublicKey(String publicKey) {
        return getPublicKey(Base64.decodeBase64(publicKey.getBytes()));
    }

    /**
     * 获取公钥
     * @param key 公钥
     * @return 公钥（X509格式）
     */
    public static RSAPublicKey getPublicKey(byte[] key) {
        try {
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(key);
            KeyFactory keyFactory = KeyFactory.getInstance(Algorithm.RSA.getAlgorithm());
            return (RSAPublicKey) keyFactory.generatePublic(keySpec);
        } catch (Exception e) {
            throw new CipherException(e);
        }
    }

    /**
     * 获取私钥（普通密钥转PKCS8格式）
     * @param privateKey 私钥（经过base64编码）
     * @return 私钥（PKCS8格式）
     */
    public static RSAPrivateKey getPrivateKey(String privateKey) {
        return getPrivateKey(Base64.decodeBase64(privateKey.getBytes()));
    }

    /**
     * 获取私钥（普通密钥转PKCS8格式）
     * @param key 私钥
     * @return 私钥（PKCS8格式）
     */
    public static RSAPrivateKey getPrivateKey(byte[] key) {
        try {
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(key);
            KeyFactory keyFactory = KeyFactory.getInstance(Algorithm.RSA.getAlgorithm());
            return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
        } catch (Exception e) {
            throw new CipherException(e);
        }
    }

    // ==================== 密钥导出导入功能（DER/PEM格式）====================

    // PEM 格式标记
    private static final String PUBLIC_KEY_PEM_HEADER = "-----BEGIN PUBLIC KEY-----";
    private static final String PUBLIC_KEY_PEM_FOOTER = "-----END PUBLIC KEY-----";
    private static final String PRIVATE_KEY_PEM_HEADER = "-----BEGIN PRIVATE KEY-----";
    private static final String PRIVATE_KEY_PEM_FOOTER = "-----END PRIVATE KEY-----";
    private static final String RSA_PRIVATE_KEY_PEM_HEADER = "-----BEGIN RSA PRIVATE KEY-----";
    private static final String RSA_PRIVATE_KEY_PEM_FOOTER = "-----END RSA PRIVATE KEY-----";

    /**
     * 导出公钥为 DER 格式（二进制）
     * @param publicKey 公钥（Base64编码的字符串）
     * @return DER 格式的公钥字节数组
     */
    public static byte[] exportPublicKeyToDER(String publicKey) {
        RSAPublicKey rsaPublicKey = getPublicKey(publicKey);
        return rsaPublicKey.getEncoded();
    }

    /**
     * 导出公钥为 DER 格式（二进制）
     * @param rsaPublicKey RSA公钥对象
     * @return DER 格式的公钥字节数组
     */
    public static byte[] exportPublicKeyToDER(RSAPublicKey rsaPublicKey) {
        return rsaPublicKey.getEncoded();
    }

    /**
     * 导出私钥为 DER 格式（二进制）
     * @param privateKey 私钥（Base64编码的字符串）
     * @return DER 格式的私钥字节数组
     */
    public static byte[] exportPrivateKeyToDER(String privateKey) {
        RSAPrivateKey rsaPrivateKey = getPrivateKey(privateKey);
        return rsaPrivateKey.getEncoded();
    }

    /**
     * 导出私钥为 DER 格式（二进制）
     * @param rsaPrivateKey RSA私钥对象
     * @return DER 格式的私钥字节数组
     */
    public static byte[] exportPrivateKeyToDER(RSAPrivateKey rsaPrivateKey) {
        return rsaPrivateKey.getEncoded();
    }

    /**
     * 导出公钥为 PEM 格式（文本）
     * @param publicKey 公钥（Base64编码的字符串）
     * @return PEM 格式的公钥字符串
     */
    public static String exportPublicKeyToPEM(String publicKey) {
        byte[] derBytes = exportPublicKeyToDER(publicKey);
        return formatToPEM(derBytes, PUBLIC_KEY_PEM_HEADER, PUBLIC_KEY_PEM_FOOTER);
    }

    /**
     * 导出公钥为 PEM 格式（文本）
     * @param rsaPublicKey RSA公钥对象
     * @return PEM 格式的公钥字符串
     */
    public static String exportPublicKeyToPEM(RSAPublicKey rsaPublicKey) {
        byte[] derBytes = exportPublicKeyToDER(rsaPublicKey);
        return formatToPEM(derBytes, PUBLIC_KEY_PEM_HEADER, PUBLIC_KEY_PEM_FOOTER);
    }

    /**
     * 导出私钥为 PEM 格式（文本，PKCS#8）
     * @param privateKey 私钥（Base64编码的字符串）
     * @return PEM 格式的私钥字符串
     */
    public static String exportPrivateKeyToPEM(String privateKey) {
        byte[] derBytes = exportPrivateKeyToDER(privateKey);
        return formatToPEM(derBytes, PRIVATE_KEY_PEM_HEADER, PRIVATE_KEY_PEM_FOOTER);
    }

    /**
     * 导出私钥为 PEM 格式（文本，PKCS#8）
     * @param rsaPrivateKey RSA私钥对象
     * @return PEM 格式的私钥字符串
     */
    public static String exportPrivateKeyToPEM(RSAPrivateKey rsaPrivateKey) {
        byte[] derBytes = exportPrivateKeyToDER(rsaPrivateKey);
        return formatToPEM(derBytes, PRIVATE_KEY_PEM_HEADER, PRIVATE_KEY_PEM_FOOTER);
    }

    /**
     * 从 DER 格式导入公钥
     * @param derBytes DER 格式的公钥字节数组
     * @return RSA公钥对象
     */
    public static RSAPublicKey importPublicKeyFromDER(byte[] derBytes) {
        return getPublicKey(derBytes);
    }

    /**
     * 从 DER 格式导入私钥
     * @param derBytes DER 格式的私钥字节数组
     * @return RSA私钥对象
     */
    public static RSAPrivateKey importPrivateKeyFromDER(byte[] derBytes) {
        return getPrivateKey(derBytes);
    }

    /**
     * 从 PEM 格式导入公钥
     * @param pemString PEM 格式的公钥字符串
     * @return RSA公钥对象
     */
    public static RSAPublicKey importPublicKeyFromPEM(String pemString) {
        byte[] derBytes = parsePEMToDER(pemString, PUBLIC_KEY_PEM_HEADER, PUBLIC_KEY_PEM_FOOTER);
        return importPublicKeyFromDER(derBytes);
    }

    /**
     * 从 PEM 格式导入私钥（支持 PKCS#8 和 PKCS#1 格式）
     * @param pemString PEM 格式的私钥字符串
     * @return RSA私钥对象
     */
    public static RSAPrivateKey importPrivateKeyFromPEM(String pemString) {
        byte[] derBytes;

        // 尝试 PKCS#8 格式
        if (pemString.contains(PRIVATE_KEY_PEM_HEADER)) {
            derBytes = parsePEMToDER(pemString, PRIVATE_KEY_PEM_HEADER, PRIVATE_KEY_PEM_FOOTER);
        }
        // 尝试 PKCS#1 格式（传统 RSA 格式）
        else if (pemString.contains(RSA_PRIVATE_KEY_PEM_HEADER)) {
            derBytes = parsePEMToDER(pemString, RSA_PRIVATE_KEY_PEM_HEADER, RSA_PRIVATE_KEY_PEM_FOOTER);
            // PKCS#1 需要转换为 PKCS#8，这里直接抛出异常提示用户
            throw new CipherException("PKCS#1 format (BEGIN RSA PRIVATE KEY) is not supported. Please use PKCS#8 format (BEGIN PRIVATE KEY)");
        } else {
            throw new CipherException("Invalid PEM format: missing header");
        }

        return importPrivateKeyFromDER(derBytes);
    }

    /**
     * 导出公钥为 DER 文件
     * @param publicKey 公钥（Base64编码的字符串）
     * @param filePath 文件路径
     */
    public static void exportPublicKeyToDERFile(String publicKey, String filePath) {
        byte[] derBytes = exportPublicKeyToDER(publicKey);
        writeToFile(derBytes, filePath);
    }

    /**
     * 导出私钥为 DER 文件
     * @param privateKey 私钥（Base64编码的字符串）
     * @param filePath 文件路径
     */
    public static void exportPrivateKeyToDERFile(String privateKey, String filePath) {
        byte[] derBytes = exportPrivateKeyToDER(privateKey);
        writeToFile(derBytes, filePath);
    }

    /**
     * 导出公钥为 PEM 文件
     * @param publicKey 公钥（Base64编码的字符串）
     * @param filePath 文件路径
     */
    public static void exportPublicKeyToPEMFile(String publicKey, String filePath) {
        String pemString = exportPublicKeyToPEM(publicKey);
        writeToFile(pemString.getBytes(), filePath);
    }

    /**
     * 导出私钥为 PEM 文件
     * @param privateKey 私钥（Base64编码的字符串）
     * @param filePath 文件路径
     */
    public static void exportPrivateKeyToPEMFile(String privateKey, String filePath) {
        String pemString = exportPrivateKeyToPEM(privateKey);
        writeToFile(pemString.getBytes(), filePath);
    }

    /**
     * 从 DER 文件导入公钥
     * @param filePath 文件路径
     * @return RSA公钥对象
     */
    public static RSAPublicKey importPublicKeyFromDERFile(String filePath) {
        byte[] derBytes = readFromFile(filePath);
        return importPublicKeyFromDER(derBytes);
    }

    /**
     * 从 DER 文件导入私钥
     * @param filePath 文件路径
     * @return RSA私钥对象
     */
    public static RSAPrivateKey importPrivateKeyFromDERFile(String filePath) {
        byte[] derBytes = readFromFile(filePath);
        return importPrivateKeyFromDER(derBytes);
    }

    /**
     * 从 PEM 文件导入公钥
     * @param filePath 文件路径
     * @return RSA公钥对象
     */
    public static RSAPublicKey importPublicKeyFromPEMFile(String filePath) {
        byte[] pemBytes = readFromFile(filePath);
        String pemString = new String(pemBytes);
        return importPublicKeyFromPEM(pemString);
    }

    /**
     * 从 PEM 文件导入私钥
     * @param filePath 文件路径
     * @return RSA私钥对象
     */
    public static RSAPrivateKey importPrivateKeyFromPEMFile(String filePath) {
        byte[] pemBytes = readFromFile(filePath);
        String pemString = new String(pemBytes);
        return importPrivateKeyFromPEM(pemString);
    }

    /**
     * 将 DER 格式转换为 PEM 格式
     * @param derBytes DER 格式的字节数组
     * @param header PEM 头部标记
     * @param footer PEM 尾部标记
     * @return PEM 格式的字符串
     */
    private static String formatToPEM(byte[] derBytes, String header, String footer) {
        String base64Encoded = Base64.encodeBase64String(derBytes);

        StringBuilder pem = new StringBuilder();
        pem.append(header).append("\n");

        // 每64个字符换行（PEM 标准）
        int index = 0;
        while (index < base64Encoded.length()) {
            int endIndex = Math.min(index + 64, base64Encoded.length());
            pem.append(base64Encoded, index, endIndex).append("\n");
            index = endIndex;
        }

        pem.append(footer);
        return pem.toString();
    }

    /**
     * 将 PEM 格式解析为 DER 格式
     * @param pemString PEM 格式的字符串
     * @param header PEM 头部标记
     * @param footer PEM 尾部标记
     * @return DER 格式的字节数组
     */
    private static byte[] parsePEMToDER(String pemString, String header, String footer) {
        // 移除头部和尾部标记
        String base64Data = pemString
                .replace(header, "")
                .replace(footer, "")
                .replaceAll("\\s", ""); // 移除所有空白字符（空格、换行等）

        // Base64 解码
        return Base64.decodeBase64(base64Data);
    }

    /**
     * 写入文件
     * @param data 数据
     * @param filePath 文件路径
     */
    private static void writeToFile(byte[] data, String filePath) {
        try {
            Files.write(Paths.get(filePath), data);
        } catch (IOException e) {
            throw new CipherException("Failed to write file: " + filePath, e);
        }
    }

    /**
     * 从文件读取
     * @param filePath 文件路径
     * @return 文件内容
     */
    private static byte[] readFromFile(String filePath) {
        try {
            return Files.readAllBytes(Paths.get(filePath));
        } catch (IOException e) {
            throw new CipherException("Failed to read file: " + filePath, e);
        }
    }

    private static void check(Mode mode, Padding padding) {
        if (mode != Mode.NONE && mode != Mode.ECB) {
            throw new CipherException("invalid RSA mode");
        }
        if (padding != Padding.PKCS1Padding && padding != Padding.NoPadding
                && padding != Padding.OAEPPadding && padding != Padding.ISO9796d1Padding) {
            throw new CipherException("invalid RSA padding");
        }
    }

}
