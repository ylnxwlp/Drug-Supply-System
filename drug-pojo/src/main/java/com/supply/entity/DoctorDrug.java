package com.supply.entity;


import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.time.LocalDate;
import java.time.LocalDateTime;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class DoctorDrug implements Serializable {

    private Long id;

    private Long userId;

    private String drugName;

    private LocalDateTime enterTime;

    private LocalDate shelfLife; //药效期

    private LocalDate producedTime; //生产日期

    private String batchNo; //药品批次号

    private String barCode; //药品69码

    private Integer drugStatus;

    private String drugCode; //药品追溯码

}
