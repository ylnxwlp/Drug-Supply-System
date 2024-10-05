package com.supply.vo;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class ReportInformationVO implements Serializable {

    private Long id;

    private String userId; //被举报人id

    private String firmName;

    private String reportUserId; //举报人id

    private Integer identity; //被举报人的身份，1为医护端，2为供应端

    private String informerFirmName; //举报人用户公司名

    private Integer informerIdentity; //举报人的身份，1为医护端，2为供应端

    private List<String> images;

    private String reason; //举报理由

    private String reportTime; //举报时间

}
