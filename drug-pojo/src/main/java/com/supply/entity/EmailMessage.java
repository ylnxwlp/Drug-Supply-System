package com.supply.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

@Builder
@AllArgsConstructor
@Data
@NoArgsConstructor
public class EmailMessage implements Serializable {

    private String emailType;

    private String emailAddress;

    private String location;

    private Long adminId;

    private String anotherEmailAddress;
}
