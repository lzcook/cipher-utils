package com.lzc.lib.util.cipher.exception;


/**
 * @author lzc
 */
public class CipherException extends RuntimeException {

    public CipherException() {
        super();
    }

    public CipherException(String message) {
        super(message);
    }

    public CipherException(Throwable cause) {
        super(cause);
    }

    public CipherException(String format, Throwable cause) {
        super(format, cause);
    }

}
