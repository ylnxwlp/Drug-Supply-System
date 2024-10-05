package com.supply.dto;


import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotEmpty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class DrugNumberChangeDTO implements Serializable {

    @Max(2)
    @Min(1)
    private Integer addOrSubtraction; //增还是减操作，1为增，2为减

    @NotEmpty
    private Integer number; //增减数量

}
