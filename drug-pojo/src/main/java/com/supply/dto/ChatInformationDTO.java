package com.supply.dto;


import jakarta.validation.constraints.NotEmpty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ChatInformationDTO implements Serializable {

    @NotEmpty
    private Long id;

    private String information;

    private String image;

}
