package com.supply.vo;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class VerificationInformationVO implements Serializable {

    private Long id;

    private String username;

    private String firmName;

    private String applicationTime;

    private List<String> images;


}
