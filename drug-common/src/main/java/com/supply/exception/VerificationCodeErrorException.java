package com.supply.exception;

public class VerificationCodeErrorException extends RuntimeException {
    public VerificationCodeErrorException() {
        super();
    }

    public VerificationCodeErrorException(String message) {
        super(message);
    }

    public VerificationCodeErrorException(String message, Throwable cause) {
        super(message, cause);
    }

    public VerificationCodeErrorException(Throwable cause) {
        super(cause);
    }

    protected VerificationCodeErrorException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
