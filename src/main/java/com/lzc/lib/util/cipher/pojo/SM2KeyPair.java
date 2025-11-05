package com.lzc.lib.util.cipher.pojo;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

/**
 * SM2公私钥
 * @author lzc
 */
public class SM2KeyPair {

    //公钥（X509格式）
    private String publicKey;

    //私钥（PKCS8格式）
    private String privateKey;

    //公钥
    private ECPublicKey ecPublicKey;

    //私钥
    private ECPrivateKey ecPrivateKey;

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

    public ECPublicKey getEcPublicKey() {
        return ecPublicKey;
    }

    public void setEcPublicKey(ECPublicKey ecPublicKey) {
        this.ecPublicKey = ecPublicKey;
    }

    public ECPrivateKey getEcPrivateKey() {
        return ecPrivateKey;
    }

    public void setEcPrivateKey(ECPrivateKey ecPrivateKey) {
        this.ecPrivateKey = ecPrivateKey;
    }
}
