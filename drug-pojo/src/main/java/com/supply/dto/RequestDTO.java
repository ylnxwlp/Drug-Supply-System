package com.supply.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class RequestDTO implements Serializable {

    // 药品名称
    private String drugName;

    // 请求克重
    private int requestWeight;

    // 供应方id
    private long producerId;

}
