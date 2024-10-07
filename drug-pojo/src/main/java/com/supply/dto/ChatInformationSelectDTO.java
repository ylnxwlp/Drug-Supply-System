package com.supply.dto;


import jakarta.validation.constraints.NotEmpty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ChatInformationSelectDTO implements Serializable {

    @NotEmpty
    private String beginTime;

    @NotEmpty
    private String EndTime;

}
