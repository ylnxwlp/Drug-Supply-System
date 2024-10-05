package com.supply.enumeration;

import java.io.Serializable;

public enum EmailType implements Serializable {
    LOGIN, CHECK_SUCCESS, CHECK_FAILURE, REPORT_WARNING, REPORT_BLOCKED, REPORT_FAILURE
}
