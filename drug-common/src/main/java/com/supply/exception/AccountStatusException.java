package com.supply.exception;

public class AccountStatusException extends RuntimeException{
    public AccountStatusException() {
        super();
    }

    public AccountStatusException(String message) {
        super(message);
    }

    public AccountStatusException(String message, Throwable cause) {
        super(message, cause);
    }

    public AccountStatusException(Throwable cause) {
        super(cause);
    }

    protected AccountStatusException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
