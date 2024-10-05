package com.supply.exception;

public class DrugInformationException extends RuntimeException{
    public DrugInformationException() {
        super();
    }

    public DrugInformationException(String message) {
        super(message);
    }

    public DrugInformationException(String message, Throwable cause) {
        super(message, cause);
    }

    public DrugInformationException(Throwable cause) {
        super(cause);
    }

    protected DrugInformationException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
