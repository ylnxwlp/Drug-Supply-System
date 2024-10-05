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
public class SupplyDrug implements Serializable {

    private Long id;

    private Long userId;

    private String drugName;

    private Integer inventoryNumber; //库存数量

    private LocalDateTime createTime;//创建时间

    private LocalDateTime updateTime; //最后修改时间
}
