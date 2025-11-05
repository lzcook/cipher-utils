package com.lzc.lib.util.cipher.asymmetry;

import com.lzc.lib.util.cipher.constant.Algorithm;
import com.lzc.lib.util.cipher.constant.Mode;
import com.lzc.lib.util.cipher.constant.Padding;
import com.lzc.lib.util.cipher.constant.RSASignType;
import com.lzc.lib.util.cipher.exception.CipherException;
import com.lzc.lib.util.cipher.pojo.RSAKeyPair;
import org.apache.commons.codec.binary.Base64;
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
 * RSA非对称加密工具类
 * 支持签名/验签、加密/解密、密钥导出导入（DER/PEM格式）
 * 默认使用OAEPWithSHA-256AndMGF1Padding填充方式
 * 详细算法说明和安全最佳实践请参考 README.md
 *
 * @author lzc
 */
public class RSAUtils {

    static {
        //导入Provider，BouncyCastle是一个开源的加解密解决方案，主页在http://www.bouncycastle.org/
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * 公钥加密（推荐方式，默认方法）
     * <p>使用 OAEP SHA-256 填充提供更高的安全性，抗选择密文攻击（CCA）</p>
     * <p>使用 RSA/ECB/OAEPWithSHA-256AndMGF1Padding，符合 NIST 推荐标准</p>
     *
     * @param data 加密内容
     * @param publicKey 公钥（X509格式，经过base64编码）
     * @return 密文（Base64编码）
     */
    public static String encryptByPublicKey(String data, String publicKey) {
        return encryptByPublicKeyOAEPSHA256(data, publicKey);
    }

    /**
     * 公钥加密（推荐方式，使用 RSA/ECB/OAEPWithSHA-256AndMGF1Padding 方式）
     * <p>使用 OAEP SHA-256 填充提供更高的安全性，抗选择密文攻击（CCA）</p>
     *
     * @param data 加密内容
     * @param publicKey 公钥（X509格式）
     * @return 密文
     */
    public static byte[] encryptByPublicKey(byte[] data, byte[] publicKey) {
        return encryptByPublicKeyOAEPSHA256(data, publicKey);
    }

    /**
     * 公钥加密（PKCS1 传统方式，不推荐）
     * <p><b>已弃用</b>：PKCS1 填充存在安全漏洞，仅用于兼容旧系统。新项目请使用默认方法或 encryptByPublicKeyOAEP</p>
     *
     * @param data 加密内容
     * @param publicKey 公钥（X509格式，经过base64编码）
     * @return 密文（Base64编码）
     * @deprecated 使用 {@link #encryptByPublicKey(String, String)} 或 {@link #encryptByPublicKeyOAEP(String, String)} 替代
     */
    @Deprecated
    public static String encryptByPublicKeyPKCS1(String data, String publicKey) {
        return encryptByPublicKey(data, publicKey, Mode.ECB, Padding.PKCS1Padding);
    }

    /**
     * 公钥加密（PKCS1 传统方式，不推荐）
     * <p><b>已弃用</b>：PKCS1 填充存在安全漏洞，仅用于兼容旧系统。新项目请使用默认方法或 encryptByPublicKeyOAEP</p>
     *
     * @param data 加密内容
     * @param publicKey 公钥（X509格式）
     * @return 密文
     * @deprecated 使用 {@link #encryptByPublicKey(byte[], byte[])} 或 {@link #encryptByPublicKeyOAEP(byte[], byte[])} 替代
     */
    @Deprecated
    public static byte[] encryptByPublicKeyPKCS1(byte[] data, byte[] publicKey) {
        return encryptByPublicKey(data, publicKey, Mode.ECB, Padding.PKCS1Padding);
    }

    /**
     * 公钥加密（PKCS#1 v1.5 方式，不推荐）
     * <p><b>已弃用</b>：PKCS#1 v1.5 填充存在安全漏洞（Bleichenbacher 攻击），仅用于兼容旧系统。新项目请使用 OAEP</p>
     * <p>注意：此方法等同于 {@link #encryptByPublicKeyPKCS1(String, String)}</p>
     *
     * @param data 加密内容
     * @param publicKey 公钥（X509格式，经过base64编码）
     * @return 密文（Base64编码）
     * @deprecated 使用 {@link #encryptByPublicKey(String, String)} 或 {@link #encryptByPublicKeyOAEP(String, String)} 替代
     */
    @Deprecated
    public static String encryptByPublicKeyPKCS1V15(String data, String publicKey) {
        return encryptByPublicKeyPKCS1(data, publicKey);
    }

    /**
     * 公钥加密（PKCS#1 v1.5 方式，不推荐）
     * <p><b>已弃用</b>：PKCS#1 v1.5 填充存在安全漏洞（Bleichenbacher 攻击），仅用于兼容旧系统。新项目请使用 OAEP</p>
     * <p>注意：此方法等同于 {@link #encryptByPublicKeyPKCS1(byte[], byte[])}</p>
     *
     * @param data 加密内容
     * @param publicKey 公钥（X509格式）
     * @return 密文
     * @deprecated 使用 {@link #encryptByPublicKey(byte[], byte[])} 或 {@link #encryptByPublicKeyOAEP(byte[], byte[])} 替代
     */
    @Deprecated
    public static byte[] encryptByPublicKeyPKCS1V15(byte[] data, byte[] publicKey) {
        return encryptByPublicKeyPKCS1(data, publicKey);
    }

    /**
     * 公钥加密（OAEP 方式，显式方法）
     * <p>使用 OAEP 填充提供更高的安全性，抗选择密文攻击（CCA）</p>
     * <p>注意：默认使用 SHA-1，推荐使用 {@link #encryptByPublicKeyOAEPSHA256} 替代</p>
     *
     * @param data 加密内容
     * @param publicKey 公钥（X509格式，经过base64编码）
     * @return 密文（Base64编码）
     */
    public static String encryptByPublicKeyOAEP(String data, String publicKey) {
        return encryptByPublicKey(data, publicKey, Mode.ECB, Padding.OAEPPadding);
    }

    /**
     * 公钥加密（OAEP 方式，显式方法）
     * <p>使用 OAEP 填充提供更高的安全性，抗选择密文攻击（CCA）</p>
     * <p>注意：默认使用 SHA-1，推荐使用 {@link #encryptByPublicKeyOAEPSHA256} 替代</p>
     *
     * @param data 加密内容
     * @param publicKey 公钥（X509格式）
     * @return 密文
     */
    public static byte[] encryptByPublicKeyOAEP(byte[] data, byte[] publicKey) {
        return encryptByPublicKey(data, publicKey, Mode.ECB, Padding.OAEPPadding);
    }

    /**
     * 公钥加密（OAEP with SHA-256，强烈推荐）
     * <p>使用 SHA-256 哈希的 OAEP 填充，符合现代安全标准（NIST 推荐）</p>
     * <p>这是所有新项目的首选方案</p>
     *
     * @param data 加密内容
     * @param publicKey 公钥（X509格式，经过base64编码）
     * @return 密文（Base64编码）
     */
    public static String encryptByPublicKeyOAEPSHA256(String data, String publicKey) {
        if (data == null || data.isEmpty()) {
            return null;
        }
        return Base64.encodeBase64String(encryptByPublicKeyOAEPSHA256(data.getBytes(), Base64.decodeBase64(publicKey)));
    }

    /**
     * 公钥加密（OAEP with SHA-256，强烈推荐）
     * <p>使用 SHA-256 哈希的 OAEP 填充，符合现代安全标准（NIST 推荐）</p>
     * <p>这是所有新项目的首选方案</p>
     *
     * @param data 加密内容
     * @param publicKey 公钥（X509格式）
     * @return 密文
     */
    public static byte[] encryptByPublicKeyOAEPSHA256(byte[] data, byte[] publicKey) {
        return encryptWithOAEPHash(data, getPublicKey(publicKey), Algorithm.SHA256);
    }

    /**
     * 公钥加密（OAEP with SHA-384，高安全场景）
     * <p>使用 SHA-384 哈希的 OAEP 填充，适用于金融、政府等高安全要求场景</p>
     *
     * @param data 加密内容
     * @param publicKey 公钥（X509格式，经过base64编码）
     * @return 密文（Base64编码）
     */
    public static String encryptByPublicKeyOAEPSHA384(String data, String publicKey) {
        if (data == null || data.isEmpty()) {
            return null;
        }
        return Base64.encodeBase64String(encryptByPublicKeyOAEPSHA384(data.getBytes(), Base64.decodeBase64(publicKey)));
    }

    /**
     * 公钥加密（OAEP with SHA-384，高安全场景）
     * <p>使用 SHA-384 哈希的 OAEP 填充，适用于金融、政府等高安全要求场景</p>
     *
     * @param data 加密内容
     * @param publicKey 公钥（X509格式）
     * @return 密文
     */
    public static byte[] encryptByPublicKeyOAEPSHA384(byte[] data, byte[] publicKey) {
        return encryptWithOAEPHash(data, getPublicKey(publicKey), Algorithm.SHA384);
    }

    /**
     * 公钥加密（OAEP with SHA-512，高安全场景）
     * <p>使用 SHA-512 哈希的 OAEP 填充，适用于金融、政府等高安全要求场景</p>
     *
     * @param data 加密内容
     * @param publicKey 公钥（X509格式，经过base64编码）
     * @return 密文（Base64编码）
     */
    public static String encryptByPublicKeyOAEPSHA512(String data, String publicKey) {
        if (data == null || data.isEmpty()) {
            return null;
        }
        return Base64.encodeBase64String(encryptByPublicKeyOAEPSHA512(data.getBytes(), Base64.decodeBase64(publicKey)));
    }

    /**
     * 公钥加密（OAEP with SHA-512，高安全场景）
     * <p>使用 SHA-512 哈希的 OAEP 填充，适用于金融、政府等高安全要求场景</p>
     *
     * @param data 加密内容
     * @param publicKey 公钥（X509格式）
     * @return 密文
     */
    public static byte[] encryptByPublicKeyOAEPSHA512(byte[] data, byte[] publicKey) {
        return encryptWithOAEPHash(data, getPublicKey(publicKey), Algorithm.SHA512);
    }

    /**
     * 使用指定哈希算法的 OAEP 填充加密
     * @param data 明文数据
     * @param rsaKey RSA密钥（公钥或私钥）
     * @param hashAlgorithm 哈希算法枚举
     * @return 密文
     */
    private static byte[] encryptWithOAEPHash(byte[] data, RSAKey rsaKey, Algorithm hashAlgorithm) {
        try {
            String hashName = hashAlgorithm.getAlgorithm();
            String algorithm = "RSA/ECB/OAEPWith" + hashName + "AndMGF1Padding";
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.ENCRYPT_MODE, (Key) rsaKey);

            // 加密时超过maxEncryptBlockSize字节就报错。为此采用分段加密的办法来加密
            int keyLength = rsaKey.getModulus().bitLength();
            // OAEP 填充的开销取决于哈希算法：SHA-256需要66字节，SHA-384需要98字节，SHA-512需要130字节
            int hashLength;
            if (hashAlgorithm == Algorithm.SHA256) {
                hashLength = 32;
            } else if (hashAlgorithm == Algorithm.SHA384) {
                hashLength = 48;
            } else if (hashAlgorithm == Algorithm.SHA512) {
                hashLength = 64;
            } else {
                hashLength = 20; // SHA-1 or default
            }
            int blockSize = keyLength / 8 - 2 * hashLength - 2;
            return segmentHandling(cipher, data, blockSize);
        } catch (Exception e) {
            throw new CipherException("RSA OAEP encrypt error with " + hashAlgorithm.getAlgorithm(), e);
        }
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
     * 私钥加密（推荐方式，默认方法）
     * <p>使用 OAEP SHA-256 填充提供更高的安全性</p>
     * <p>使用 RSA/ECB/OAEPWithSHA-256AndMGF1Padding，符合 NIST 推荐标准</p>
     * <p>注意：私钥加密通常用于签名场景，建议使用 {@link #sign} 方法</p>
     *
     * @param data 加密内容
     * @param privateKey 私钥
     * @return 密文（Base64编码）
     */
    public static String encryptByPrivateKey(String data, String privateKey) {
        return encryptByPrivateKeyOAEPSHA256(data, privateKey);
    }

    /**
     * 私钥加密（推荐方式，使用 RSA/ECB/OAEPWithSHA-256AndMGF1Padding 方式）
     * <p>使用 OAEP SHA-256 填充提供更高的安全性</p>
     * <p>注意：私钥加密通常用于签名场景，建议使用 {@link #sign} 方法</p>
     *
     * @param data 加密内容
     * @param privateKey 私钥
     * @return 密文
     */
    public static byte[] encryptByPrivateKey(byte[] data, byte[] privateKey) {
        return encryptByPrivateKeyOAEPSHA256(data, privateKey);
    }

    /**
     * 私钥加密（PKCS1 传统方式，不推荐）
     * <p><b>已弃用</b>：PKCS1 填充存在安全漏洞，仅用于兼容旧系统</p>
     * <p>注意：私钥加密通常用于签名场景，建议使用 {@link #sign} 方法</p>
     *
     * @param data 加密内容
     * @param privateKey 私钥
     * @return 密文（Base64编码）
     * @deprecated 使用 {@link #encryptByPrivateKey(String, String)} 或 {@link #encryptByPrivateKeyOAEP(String, String)} 替代
     */
    @Deprecated
    public static String encryptByPrivateKeyPKCS1(String data, String privateKey) {
        return encryptByPrivateKey(data, privateKey, Mode.ECB, Padding.PKCS1Padding);
    }

    /**
     * 私钥加密（PKCS1 传统方式，不推荐）
     * <p><b>已弃用</b>：PKCS1 填充存在安全漏洞，仅用于兼容旧系统</p>
     * <p>注意：私钥加密通常用于签名场景，建议使用 {@link #sign} 方法</p>
     *
     * @param data 加密内容
     * @param privateKey 私钥
     * @return 密文
     * @deprecated 使用 {@link #encryptByPrivateKey(byte[], byte[])} 或 {@link #encryptByPrivateKeyOAEP(byte[], byte[])} 替代
     */
    @Deprecated
    public static byte[] encryptByPrivateKeyPKCS1(byte[] data, byte[] privateKey) {
        return encryptByPrivateKey(data, privateKey, Mode.ECB, Padding.PKCS1Padding);
    }

    /**
     * 私钥加密（PKCS#1 v1.5 方式，不推荐）
     * <p><b>已弃用</b>：PKCS#1 v1.5 填充存在安全漏洞（Bleichenbacher 攻击），仅用于兼容旧系统。新项目请使用 OAEP</p>
     * <p>注意：私钥加密通常用于签名场景，建议使用 {@link #sign} 方法</p>
     * <p>注意：此方法等同于 {@link #encryptByPrivateKeyPKCS1(String, String)}</p>
     *
     * @param data 加密内容
     * @param privateKey 私钥（PKCS8格式，经过base64编码）
     * @return 密文（Base64编码）
     * @deprecated 使用 {@link #encryptByPrivateKey(String, String)} 或 {@link #encryptByPrivateKeyOAEP(String, String)} 替代
     */
    @Deprecated
    public static String encryptByPrivateKeyPKCS1V15(String data, String privateKey) {
        return encryptByPrivateKeyPKCS1(data, privateKey);
    }

    /**
     * 私钥加密（PKCS#1 v1.5 方式，不推荐）
     * <p><b>已弃用</b>：PKCS#1 v1.5 填充存在安全漏洞（Bleichenbacher 攻击），仅用于兼容旧系统。新项目请使用 OAEP</p>
     * <p>注意：私钥加密通常用于签名场景，建议使用 {@link #sign} 方法</p>
     * <p>注意：此方法等同于 {@link #encryptByPrivateKeyPKCS1(byte[], byte[])}</p>
     *
     * @param data 加密内容
     * @param privateKey 私钥（PKCS8格式）
     * @return 密文
     * @deprecated 使用 {@link #encryptByPrivateKey(byte[], byte[])} 或 {@link #encryptByPrivateKeyOAEP(byte[], byte[])} 替代
     */
    @Deprecated
    public static byte[] encryptByPrivateKeyPKCS1V15(byte[] data, byte[] privateKey) {
        return encryptByPrivateKeyPKCS1(data, privateKey);
    }

    /**
     * 私钥加密（OAEP 方式，显式方法）
     * <p>使用 OAEP 填充提供更高的安全性</p>
     * <p>注意：私钥加密通常用于签名场景，建议使用 {@link #sign} 方法</p>
     *
     * @param data 加密内容
     * @param privateKey 私钥
     * @return 密文（Base64编码）
     */
    public static String encryptByPrivateKeyOAEP(String data, String privateKey) {
        return encryptByPrivateKey(data, privateKey, Mode.ECB, Padding.OAEPPadding);
    }

    /**
     * 私钥加密（OAEP 方式，显式方法）
     * <p>使用 OAEP 填充提供更高的安全性</p>
     * <p>注意：私钥加密通常用于签名场景，建议使用 {@link #sign} 方法</p>
     *
     * @param data 加密内容
     * @param privateKey 私钥
     * @return 密文
     */
    public static byte[] encryptByPrivateKeyOAEP(byte[] data, byte[] privateKey) {
        return encryptByPrivateKey(data, privateKey, Mode.ECB, Padding.OAEPPadding);
    }

    /**
     * 私钥加密（OAEP with SHA-256，强烈推荐）
     * <p>使用 SHA-256 哈希的 OAEP 填充，符合现代安全标准（NIST 推荐）</p>
     * <p>注意：私钥加密通常用于签名场景，建议使用 {@link #sign} 方法</p>
     *
     * @param data 加密内容
     * @param privateKey 私钥（PKCS8格式，经过base64编码）
     * @return 密文（Base64编码）
     */
    public static String encryptByPrivateKeyOAEPSHA256(String data, String privateKey) {
        if (data == null || data.isEmpty()) {
            return null;
        }
        return Base64.encodeBase64String(encryptByPrivateKeyOAEPSHA256(data.getBytes(), Base64.decodeBase64(privateKey)));
    }

    /**
     * 私钥加密（OAEP with SHA-256，强烈推荐）
     * <p>使用 SHA-256 哈希的 OAEP 填充，符合现代安全标准（NIST 推荐）</p>
     * <p>注意：私钥加密通常用于签名场景，建议使用 {@link #sign} 方法</p>
     *
     * @param data 加密内容
     * @param privateKey 私钥（PKCS8格式）
     * @return 密文
     */
    public static byte[] encryptByPrivateKeyOAEPSHA256(byte[] data, byte[] privateKey) {
        return encryptWithOAEPHash(data, getPrivateKey(privateKey), Algorithm.SHA256);
    }

    /**
     * 私钥加密（OAEP with SHA-384，高安全场景）
     * <p>使用 SHA-384 哈希的 OAEP 填充，适用于金融、政府等高安全要求场景</p>
     * <p>注意：私钥加密通常用于签名场景，建议使用 {@link #sign} 方法</p>
     *
     * @param data 加密内容
     * @param privateKey 私钥（PKCS8格式，经过base64编码）
     * @return 密文（Base64编码）
     */
    public static String encryptByPrivateKeyOAEPSHA384(String data, String privateKey) {
        if (data == null || data.isEmpty()) {
            return null;
        }
        return Base64.encodeBase64String(encryptByPrivateKeyOAEPSHA384(data.getBytes(), Base64.decodeBase64(privateKey)));
    }

    /**
     * 私钥加密（OAEP with SHA-384，高安全场景）
     * <p>使用 SHA-384 哈希的 OAEP 填充，适用于金融、政府等高安全要求场景</p>
     * <p>注意：私钥加密通常用于签名场景，建议使用 {@link #sign} 方法</p>
     *
     * @param data 加密内容
     * @param privateKey 私钥（PKCS8格式）
     * @return 密文
     */
    public static byte[] encryptByPrivateKeyOAEPSHA384(byte[] data, byte[] privateKey) {
        return encryptWithOAEPHash(data, getPrivateKey(privateKey), Algorithm.SHA384);
    }

    /**
     * 私钥加密（OAEP with SHA-512，高安全场景）
     * <p>使用 SHA-512 哈希的 OAEP 填充，适用于金融、政府等高安全要求场景</p>
     * <p>注意：私钥加密通常用于签名场景，建议使用 {@link #sign} 方法</p>
     *
     * @param data 加密内容
     * @param privateKey 私钥（PKCS8格式，经过base64编码）
     * @return 密文（Base64编码）
     */
    public static String encryptByPrivateKeyOAEPSHA512(String data, String privateKey) {
        if (data == null || data.isEmpty()) {
            return null;
        }
        return Base64.encodeBase64String(encryptByPrivateKeyOAEPSHA512(data.getBytes(), Base64.decodeBase64(privateKey)));
    }

    /**
     * 私钥加密（OAEP with SHA-512，高安全场景）
     * <p>使用 SHA-512 哈希的 OAEP 填充，适用于金融、政府等高安全要求场景</p>
     * <p>注意：私钥加密通常用于签名场景，建议使用 {@link #sign} 方法</p>
     *
     * @param data 加密内容
     * @param privateKey 私钥（PKCS8格式）
     * @return 密文
     */
    public static byte[] encryptByPrivateKeyOAEPSHA512(byte[] data, byte[] privateKey) {
        return encryptWithOAEPHash(data, getPrivateKey(privateKey), Algorithm.SHA512);
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
        if (data == null || data.isEmpty()) {
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
     * 公钥解密（推荐方式，默认方法）
     * <p>使用 OAEP SHA-256 填充提供更高的安全性</p>
     * <p>使用 RSA/ECB/OAEPWithSHA-256AndMGF1Padding，符合 NIST 推荐标准</p>
     * <p>注意：公钥解密通常用于验签场景，建议使用 {@link #verifySign} 方法</p>
     *
     * @param data 密文（Base64编码）
     * @param publicKey 公钥
     * @return 明文
     */
    public static String decryptByPublicKey(String data, String publicKey) {
        return decryptByPublicKeyOAEPSHA256(data, publicKey);
    }

    /**
     * 公钥解密（推荐方式，使用 RSA/ECB/OAEPWithSHA-256AndMGF1Padding 方式）
     * <p>使用 OAEP SHA-256 填充提供更高的安全性</p>
     * <p>注意：公钥解密通常用于验签场景，建议使用 {@link #verifySign} 方法</p>
     *
     * @param data 密文
     * @param publicKey 公钥
     * @return 明文
     */
    public static byte[] decryptByPublicKey(byte[] data, String publicKey) {
        return decryptByPublicKeyOAEPSHA256(data, publicKey);
    }

    /**
     * 公钥解密（PKCS1 传统方式，不推荐）
     * <p><b>已弃用</b>：PKCS1 填充存在安全漏洞，仅用于兼容旧系统</p>
     *
     * @param data 密文（Base64编码）
     * @param publicKey 公钥
     * @return 明文
     * @deprecated 使用 {@link #decryptByPublicKey(String, String)} 或 {@link #decryptByPublicKeyOAEP(String, String)} 替代
     */
    @Deprecated
    public static String decryptByPublicKeyPKCS1(String data, String publicKey) {
        return decryptByPublicKey(data, publicKey, Mode.ECB, Padding.PKCS1Padding);
    }

    /**
     * 公钥解密（PKCS1 传统方式，不推荐）
     * <p><b>已弃用</b>：PKCS1 填充存在安全漏洞，仅用于兼容旧系统</p>
     *
     * @param data 密文
     * @param publicKey 公钥
     * @return 明文
     * @deprecated 使用 {@link #decryptByPublicKey(byte[], String)} 或 {@link #decryptByPublicKeyOAEP(byte[], String)} 替代
     */
    @Deprecated
    public static byte[] decryptByPublicKeyPKCS1(byte[] data, String publicKey) {
        return decryptByPublicKey(data, publicKey, Mode.ECB, Padding.PKCS1Padding);
    }

    /**
     * 公钥解密（PKCS#1 v1.5 方式，不推荐）
     * <p><b>已弃用</b>：PKCS#1 v1.5 填充存在安全漏洞（Bleichenbacher 攻击），仅用于兼容旧系统。新项目请使用 OAEP</p>
     * <p>注意：此方法等同于 {@link #decryptByPublicKeyPKCS1(String, String)}</p>
     *
     * @param data 密文（Base64编码）
     * @param publicKey 公钥（X509格式，经过base64编码）
     * @return 明文
     * @deprecated 使用 {@link #decryptByPublicKey(String, String)} 或 {@link #decryptByPublicKeyOAEP(String, String)} 替代
     */
    @Deprecated
    public static String decryptByPublicKeyPKCS1V15(String data, String publicKey) {
        return decryptByPublicKeyPKCS1(data, publicKey);
    }

    /**
     * 公钥解密（PKCS#1 v1.5 方式，不推荐）
     * <p><b>已弃用</b>：PKCS#1 v1.5 填充存在安全漏洞（Bleichenbacher 攻击），仅用于兼容旧系统。新项目请使用 OAEP</p>
     * <p>注意：此方法等同于 {@link #decryptByPublicKeyPKCS1(byte[], String)}</p>
     *
     * @param data 密文
     * @param publicKey 公钥（X509格式，经过base64编码）
     * @return 明文
     * @deprecated 使用 {@link #decryptByPublicKey(byte[], String)} 或 {@link #decryptByPublicKeyOAEP(byte[], String)} 替代
     */
    @Deprecated
    public static byte[] decryptByPublicKeyPKCS1V15(byte[] data, String publicKey) {
        return decryptByPublicKeyPKCS1(data, publicKey);
    }

    /**
     * 公钥解密（OAEP 方式，显式方法）
     * <p>使用 OAEP 填充提供更高的安全性</p>
     *
     * @param data 密文（Base64编码）
     * @param publicKey 公钥
     * @return 明文
     */
    public static String decryptByPublicKeyOAEP(String data, String publicKey) {
        return decryptByPublicKey(data, publicKey, Mode.ECB, Padding.OAEPPadding);
    }

    /**
     * 公钥解密（OAEP 方式，显式方法）
     * <p>使用 OAEP 填充提供更高的安全性</p>
     *
     * @param data 密文
     * @param publicKey 公钥
     * @return 明文
     */
    public static byte[] decryptByPublicKeyOAEP(byte[] data, String publicKey) {
        return decryptByPublicKey(data, publicKey, Mode.ECB, Padding.OAEPPadding);
    }

    /**
     * 公钥解密（OAEP with SHA-256，强烈推荐）
     * <p>使用 SHA-256 哈希的 OAEP 填充，符合现代安全标准（NIST 推荐）</p>
     * <p>注意：公钥解密通常用于验签场景，建议使用 {@link #verifySign} 方法</p>
     *
     * @param data 密文（Base64编码）
     * @param publicKey 公钥（X509格式，经过base64编码）
     * @return 明文
     */
    public static String decryptByPublicKeyOAEPSHA256(String data, String publicKey) {
        if (data == null || data.isEmpty()) {
            return null;
        }
        byte[] decrypt = decryptByPublicKeyOAEPSHA256(Base64.decodeBase64(data.getBytes()), publicKey);
        return new String(decrypt);
    }

    /**
     * 公钥解密（OAEP with SHA-256，强烈推荐）
     * <p>使用 SHA-256 哈希的 OAEP 填充，符合现代安全标准（NIST 推荐）</p>
     * <p>注意：公钥解密通常用于验签场景，建议使用 {@link #verifySign} 方法</p>
     *
     * @param data 密文
     * @param publicKey 公钥（X509格式，经过base64编码）
     * @return 明文
     */
    public static byte[] decryptByPublicKeyOAEPSHA256(byte[] data, String publicKey) {
        return decryptWithOAEPHash(data, getPublicKey(publicKey), Algorithm.SHA256);
    }

    /**
     * 公钥解密（OAEP with SHA-384，高安全场景）
     * <p>使用 SHA-384 哈希的 OAEP 填充，适用于金融、政府等高安全要求场景</p>
     * <p>注意：公钥解密通常用于验签场景，建议使用 {@link #verifySign} 方法</p>
     *
     * @param data 密文（Base64编码）
     * @param publicKey 公钥（X509格式，经过base64编码）
     * @return 明文
     */
    public static String decryptByPublicKeyOAEPSHA384(String data, String publicKey) {
        if (data == null || data.isEmpty()) {
            return null;
        }
        byte[] decrypt = decryptByPublicKeyOAEPSHA384(Base64.decodeBase64(data.getBytes()), publicKey);
        return new String(decrypt);
    }

    /**
     * 公钥解密（OAEP with SHA-384，高安全场景）
     * <p>使用 SHA-384 哈希的 OAEP 填充，适用于金融、政府等高安全要求场景</p>
     * <p>注意：公钥解密通常用于验签场景，建议使用 {@link #verifySign} 方法</p>
     *
     * @param data 密文
     * @param publicKey 公钥（X509格式，经过base64编码）
     * @return 明文
     */
    public static byte[] decryptByPublicKeyOAEPSHA384(byte[] data, String publicKey) {
        return decryptWithOAEPHash(data, getPublicKey(publicKey), Algorithm.SHA384);
    }

    /**
     * 公钥解密（OAEP with SHA-512，高安全场景）
     * <p>使用 SHA-512 哈希的 OAEP 填充，适用于金融、政府等高安全要求场景</p>
     * <p>注意：公钥解密通常用于验签场景，建议使用 {@link #verifySign} 方法</p>
     *
     * @param data 密文（Base64编码）
     * @param publicKey 公钥（X509格式，经过base64编码）
     * @return 明文
     */
    public static String decryptByPublicKeyOAEPSHA512(String data, String publicKey) {
        if (data == null || data.isEmpty()) {
            return null;
        }
        byte[] decrypt = decryptByPublicKeyOAEPSHA512(Base64.decodeBase64(data.getBytes()), publicKey);
        return new String(decrypt);
    }

    /**
     * 公钥解密（OAEP with SHA-512，高安全场景）
     * <p>使用 SHA-512 哈希的 OAEP 填充，适用于金融、政府等高安全要求场景</p>
     * <p>注意：公钥解密通常用于验签场景，建议使用 {@link #verifySign} 方法</p>
     *
     * @param data 密文
     * @param publicKey 公钥（X509格式，经过base64编码）
     * @return 明文
     */
    public static byte[] decryptByPublicKeyOAEPSHA512(byte[] data, String publicKey) {
        return decryptWithOAEPHash(data, getPublicKey(publicKey), Algorithm.SHA512);
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
     * 私钥解密（推荐方式，默认方法）
     * <p>使用 OAEP SHA-256 填充提供更高的安全性，抗选择密文攻击（CCA）</p>
     * <p>使用 RSA/ECB/OAEPWithSHA-256AndMGF1Padding，符合 NIST 推荐标准</p>
     *
     * @param data 密文（Base64编码）
     * @param privateKey 私钥
     * @return 明文
     */
    public static String decryptByPrivateKey(String data, String privateKey) {
        return decryptByPrivateKeyOAEPSHA256(data, privateKey);
    }

    /**
     * 私钥解密（推荐方式，使用 RSA/ECB/OAEPWithSHA-256AndMGF1Padding 方式）
     * <p>使用 OAEP SHA-256 填充提供更高的安全性，抗选择密文攻击（CCA）</p>
     *
     * @param data 密文
     * @param privateKey 私钥
     * @return 明文
     */
    public static byte[] decryptByPrivateKey(byte[] data, String privateKey) {
        return decryptByPrivateKeyOAEPSHA256(data, privateKey);
    }

    /**
     * 私钥解密（PKCS1 传统方式，不推荐）
     * <p><b>已弃用</b>：PKCS1 填充存在安全漏洞，仅用于兼容旧系统。新项目请使用默认方法或 decryptByPrivateKeyOAEP</p>
     *
     * @param data 密文（Base64编码）
     * @param privateKey 私钥
     * @return 明文
     * @deprecated 使用 {@link #decryptByPrivateKey(String, String)} 或 {@link #decryptByPrivateKeyOAEP(String, String)} 替代
     */
    @Deprecated
    public static String decryptByPrivateKeyPKCS1(String data, String privateKey) {
        return decryptByPrivateKey(data, privateKey, Mode.ECB, Padding.PKCS1Padding);
    }

    /**
     * 私钥解密（PKCS1 传统方式，不推荐）
     * <p><b>已弃用</b>：PKCS1 填充存在安全漏洞，仅用于兼容旧系统。新项目请使用默认方法或 decryptByPrivateKeyOAEP</p>
     *
     * @param data 密文
     * @param privateKey 私钥
     * @return 明文
     * @deprecated 使用 {@link #decryptByPrivateKey(byte[], String)} 或 {@link #decryptByPrivateKeyOAEP(byte[], String)} 替代
     */
    @Deprecated
    public static byte[] decryptByPrivateKeyPKCS1(byte[] data, String privateKey) {
        return decryptByPrivateKey(data, privateKey, Mode.ECB, Padding.PKCS1Padding);
    }

    /**
     * 私钥解密（PKCS#1 v1.5 方式，不推荐）
     * <p><b>已弃用</b>：PKCS#1 v1.5 填充存在安全漏洞（Bleichenbacher 攻击），仅用于兼容旧系统。新项目请使用 OAEP</p>
     * <p>注意：此方法等同于 {@link #decryptByPrivateKeyPKCS1(String, String)}</p>
     *
     * @param data 密文（Base64编码）
     * @param privateKey 私钥（PKCS8格式，经过base64编码）
     * @return 明文
     * @deprecated 使用 {@link #decryptByPrivateKey(String, String)} 或 {@link #decryptByPrivateKeyOAEP(String, String)} 替代
     */
    @Deprecated
    public static String decryptByPrivateKeyPKCS1V15(String data, String privateKey) {
        return decryptByPrivateKeyPKCS1(data, privateKey);
    }

    /**
     * 私钥解密（PKCS#1 v1.5 方式，不推荐）
     * <p><b>已弃用</b>：PKCS#1 v1.5 填充存在安全漏洞（Bleichenbacher 攻击），仅用于兼容旧系统。新项目请使用 OAEP</p>
     * <p>注意：此方法等同于 {@link #decryptByPrivateKeyPKCS1(byte[], String)}</p>
     *
     * @param data 密文
     * @param privateKey 私钥（PKCS8格式，经过base64编码）
     * @return 明文
     * @deprecated 使用 {@link #decryptByPrivateKey(byte[], String)} 或 {@link #decryptByPrivateKeyOAEP(byte[], String)} 替代
     */
    @Deprecated
    public static byte[] decryptByPrivateKeyPKCS1V15(byte[] data, String privateKey) {
        return decryptByPrivateKeyPKCS1(data, privateKey);
    }

    /**
     * 私钥解密（OAEP 方式，显式方法）
     * <p>使用 OAEP 填充提供更高的安全性，抗选择密文攻击（CCA）</p>
     *
     * @param data 密文（Base64编码）
     * @param privateKey 私钥
     * @return 明文
     */
    public static String decryptByPrivateKeyOAEP(String data, String privateKey) {
        return decryptByPrivateKey(data, privateKey, Mode.ECB, Padding.OAEPPadding);
    }

    /**
     * 私钥解密（OAEP 方式，显式方法）
     * <p>使用 OAEP 填充提供更高的安全性，抗选择密文攻击（CCA）</p>
     *
     * @param data 密文
     * @param privateKey 私钥
     * @return 明文
     */
    public static byte[] decryptByPrivateKeyOAEP(byte[] data, String privateKey) {
        return decryptByPrivateKey(data, privateKey, Mode.ECB, Padding.OAEPPadding);
    }

    /**
     * 私钥解密（OAEP with SHA-256，强烈推荐）
     * <p>使用 SHA-256 哈希的 OAEP 填充，符合现代安全标准（NIST 推荐）</p>
     *
     * @param data 密文（Base64编码）
     * @param privateKey 私钥（PKCS8格式，经过base64编码）
     * @return 明文
     */
    public static String decryptByPrivateKeyOAEPSHA256(String data, String privateKey) {
        if (data == null || data.isEmpty()) {
            return null;
        }
        byte[] decrypt = decryptByPrivateKeyOAEPSHA256(Base64.decodeBase64(data.getBytes()), privateKey);
        return new String(decrypt);
    }

    /**
     * 私钥解密（OAEP with SHA-256，强烈推荐）
     * <p>使用 SHA-256 哈希的 OAEP 填充，符合现代安全标准（NIST 推荐）</p>
     *
     * @param data 密文
     * @param privateKey 私钥（PKCS8格式，经过base64编码）
     * @return 明文
     */
    public static byte[] decryptByPrivateKeyOAEPSHA256(byte[] data, String privateKey) {
        return decryptWithOAEPHash(data, getPrivateKey(privateKey), Algorithm.SHA256);
    }

    /**
     * 私钥解密（OAEP with SHA-384，高安全场景）
     * <p>使用 SHA-384 哈希的 OAEP 填充，适用于金融、政府等高安全要求场景</p>
     *
     * @param data 密文（Base64编码）
     * @param privateKey 私钥（PKCS8格式，经过base64编码）
     * @return 明文
     */
    public static String decryptByPrivateKeyOAEPSHA384(String data, String privateKey) {
        if (data == null || data.isEmpty()) {
            return null;
        }
        byte[] decrypt = decryptByPrivateKeyOAEPSHA384(Base64.decodeBase64(data.getBytes()), privateKey);
        return new String(decrypt);
    }

    /**
     * 私钥解密（OAEP with SHA-384，高安全场景）
     * <p>使用 SHA-384 哈希的 OAEP 填充，适用于金融、政府等高安全要求场景</p>
     *
     * @param data 密文
     * @param privateKey 私钥（PKCS8格式，经过base64编码）
     * @return 明文
     */
    public static byte[] decryptByPrivateKeyOAEPSHA384(byte[] data, String privateKey) {
        return decryptWithOAEPHash(data, getPrivateKey(privateKey), Algorithm.SHA384);
    }

    /**
     * 私钥解密（OAEP with SHA-512，高安全场景）
     * <p>使用 SHA-512 哈希的 OAEP 填充，适用于金融、政府等高安全要求场景</p>
     *
     * @param data 密文（Base64编码）
     * @param privateKey 私钥（PKCS8格式，经过base64编码）
     * @return 明文
     */
    public static String decryptByPrivateKeyOAEPSHA512(String data, String privateKey) {
        if (data == null || data.isEmpty()) {
            return null;
        }
        byte[] decrypt = decryptByPrivateKeyOAEPSHA512(Base64.decodeBase64(data.getBytes()), privateKey);
        return new String(decrypt);
    }

    /**
     * 私钥解密（OAEP with SHA-512，高安全场景）
     * <p>使用 SHA-512 哈希的 OAEP 填充，适用于金融、政府等高安全要求场景</p>
     *
     * @param data 密文
     * @param privateKey 私钥（PKCS8格式，经过base64编码）
     * @return 明文
     */
    public static byte[] decryptByPrivateKeyOAEPSHA512(byte[] data, String privateKey) {
        return decryptWithOAEPHash(data, getPrivateKey(privateKey), Algorithm.SHA512);
    }

    /**
     * 使用指定哈希算法的 OAEP 填充解密
     * @param data 密文数据
     * @param rsaKey RSA密钥（公钥或私钥）
     * @param hashAlgorithm 哈希算法枚举
     * @return 明文
     */
    private static byte[] decryptWithOAEPHash(byte[] data, RSAKey rsaKey, Algorithm hashAlgorithm) {
        try {
            String hashName = hashAlgorithm.getAlgorithm();
            String algorithm = "RSA/ECB/OAEPWith" + hashName + "AndMGF1Padding";
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.DECRYPT_MODE, (Key) rsaKey);

            // 解密时超过maxDecryptBlockSize字节就报错。为此采用分段解密的办法来解密
            int keyLength = rsaKey.getModulus().bitLength();
            int blockSize = keyLength / 8;
            return segmentHandling(cipher, data, blockSize);
        } catch (Exception e) {
            throw new CipherException("RSA OAEP decrypt error with " + hashAlgorithm.getAlgorithm(), e);
        }
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
        if (data == null || data.isEmpty()) {
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
        return getPublicKey(Base64.decodeBase64(publicKey));
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
        return getPrivateKey(Base64.decodeBase64(privateKey));
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
