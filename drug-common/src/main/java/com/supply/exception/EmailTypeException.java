package com.supply.exception;

public class EmailTypeException extends RuntimeException {

    public EmailTypeException() {
        super();
    }

    public EmailTypeException(String message) {
        super(message);
    }

    public EmailTypeException(String message, Throwable cause) {
        super(message, cause);
    }

    public EmailTypeException(Throwable cause) {
        super(cause);
    }

    protected EmailTypeException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
