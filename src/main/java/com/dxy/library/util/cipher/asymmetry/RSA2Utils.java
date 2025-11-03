package com.dxy.library.util.cipher.asymmetry;

import com.dxy.library.util.cipher.exception.CipherException;
import org.apache.commons.codec.binary.Base64;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * RSA 密钥导出导入扩展工具类
 * 支持 DER 和 PEM 格式的密钥导出导入
 *
 * DER (Distinguished Encoding Rules): 二进制格式
 * PEM (Privacy Enhanced Mail): Base64 编码的文本格式，带有 BEGIN/END 标记
 *
 * @author duanxinyuan
 * 2025/11/03
 */
public class RSA2Utils {

    // PEM 格式标记
    private static final String PUBLIC_KEY_PEM_HEADER = "-----BEGIN PUBLIC KEY-----";
    private static final String PUBLIC_KEY_PEM_FOOTER = "-----END PUBLIC KEY-----";
    private static final String PRIVATE_KEY_PEM_HEADER = "-----BEGIN PRIVATE KEY-----";
    private static final String PRIVATE_KEY_PEM_FOOTER = "-----END PRIVATE KEY-----";

    // RSA PKCS#1 格式标记（可选）
    private static final String RSA_PRIVATE_KEY_PEM_HEADER = "-----BEGIN RSA PRIVATE KEY-----";
    private static final String RSA_PRIVATE_KEY_PEM_FOOTER = "-----END RSA PRIVATE KEY-----";

    /**
     * 导出公钥为 DER 格式（二进制）
     * @param publicKey 公钥（Base64编码的字符串）
     * @return DER 格式的公钥字节数组
     */
    public static byte[] exportPublicKeyToDER(String publicKey) {
        RSAPublicKey rsaPublicKey = RSAUtils.getPublicKey(publicKey);
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
        RSAPrivateKey rsaPrivateKey = RSAUtils.getPrivateKey(privateKey);
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
        return RSAUtils.getPublicKey(derBytes);
    }

    /**
     * 从 DER 格式导入私钥
     * @param derBytes DER 格式的私钥字节数组
     * @return RSA私钥对象
     */
    public static RSAPrivateKey importPrivateKeyFromDER(byte[] derBytes) {
        return RSAUtils.getPrivateKey(derBytes);
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

}
