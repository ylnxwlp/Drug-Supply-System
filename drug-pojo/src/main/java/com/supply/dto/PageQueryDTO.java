package com.supply.dto;

import lombok.Data;

import java.io.Serializable;

@Data
public class PageQueryDTO implements Serializable {

    private int page;

    private int pageSize;
}
