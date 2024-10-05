package com.supply.vo;


import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class RequestVO implements Serializable {

    private Long id;

    private Long userId;

    private String username;

    private String image;

    private String requestContent;

    private String requestTime;

    private Integer requestStatus; //请求状态1为同意，2为未同意,3为待操作
}
