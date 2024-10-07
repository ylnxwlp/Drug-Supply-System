package com.supply.dto;


import jakarta.validation.constraints.NotEmpty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ReportDTO implements Serializable {

    @NotEmpty
    private Long id;

    @NotEmpty
    private String reason;

    @NotEmpty
    private List<String> images;

}
