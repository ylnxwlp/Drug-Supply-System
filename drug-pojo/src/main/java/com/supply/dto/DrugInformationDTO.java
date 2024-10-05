package com.supply.dto;


import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class DrugInformationDTO implements Serializable {

    private String drugName; //新药品名

    private Integer inventoryNumber; // 新药品库存数量

}
