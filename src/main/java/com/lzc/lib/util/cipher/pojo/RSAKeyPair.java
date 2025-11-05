package com.lzc.lib.util.cipher.pojo;

import lombok.Data;

import java.math.BigInteger;

/**
 * RSA公私钥
 * @author lzc
 */
@Data
public class RSAKeyPair {

    //公钥（Base64编码）
    private String publicKey;

    //私钥（Base64编码）
    private String privateKey;

    //模数
    private BigInteger modules;

}
