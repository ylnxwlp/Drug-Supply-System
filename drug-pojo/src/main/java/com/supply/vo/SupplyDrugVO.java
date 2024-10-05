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
public class SupplyDrugVO implements Serializable {

    private Long id;

    private String drugName;

    private Integer inventoryNumber; //库存数量

    private String lastModificationTime; //最后修改时间
}
