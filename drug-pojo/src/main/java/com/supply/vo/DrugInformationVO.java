package com.supply.vo;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class DrugInformationVO implements Serializable {

    private Long id;

    // 药品名称
    private String drugName;

    // 库存数量（盒）
    private Integer inventoryNumber;

    // 所属供应商公司名
    private List<String> firmsName;

}
