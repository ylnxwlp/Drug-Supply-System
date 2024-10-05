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
public class Report implements Serializable {

    private Long id;

    private Long userId; //被举报人id

    private Long reportUserId; //举报人id

    private String reason;

    private Integer identity; //被举报人身份，1为医护端，2为供应端

    private Integer reporterIdentity; //举报人身份

    private String images;

    private LocalDateTime reportTime;

    private Integer reportStatus; //审核状态，1为未审核，2为已审核


}
