package com.lzc.lib.util.cipher.pojo;

import java.math.BigInteger;

/**
 * RSA公私钥
 * @author lzc
 */
public class RSAKeyPair {

    //公钥（Base64编码）
    private String publicKey;

    //私钥（Base64编码）
    private String privateKey;

    //模数
    private BigInteger modules;

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public String getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(String privateKey) {
        this.privateKey = privateKey;
    }

    public BigInteger getModules() {
        return modules;
    }

    public void setModules(BigInteger modules) {
        this.modules = modules;
    }
}
