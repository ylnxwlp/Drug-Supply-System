package com.supply.entity;


import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.time.LocalDateTime;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class Request implements Serializable {

    private Long id;

    private Long requestUserId;

    private Long userId;

    private Integer isAgree;

    private String requestContent;

    private LocalDateTime requestTime;

    private LocalDateTime responseTime;

}
