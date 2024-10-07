package com.supply.vo;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class DrugShortageVO implements Serializable {

    private Long id;

    private String drugName;

    private Integer inventoryNumber;
}
