package com.supply.vo;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class DrugStatisticVO implements Serializable {

    // 药品名称
    private String drugName;

    // 药品出库时间（模糊到月）
    private String deleteTime;

    // 药品出库数量
    private Integer deleteAmount;

    // 药品入库时间（模糊到月）
    private String enterTime;

    // 药品入库数量
    private Integer enterAmount;



}
