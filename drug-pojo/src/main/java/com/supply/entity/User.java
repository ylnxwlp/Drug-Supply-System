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
public class User implements Serializable {

    private Long id;

    private String username;

    private String firmName;

    private Integer workType; //工种，1为医护端，2为供应端，3为管理端

    private String image;

    private String email;

    private Integer accountStatus; //账户状态，1为正常，2为锁定，3为未审核，4为审核未通过

    private String telephone;

    private String password;

    private String resume; //个人简介

    private LocalDateTime createTime;

    private LocalDateTime updateTime;

    private Integer age;

    private String idNumber;

}
