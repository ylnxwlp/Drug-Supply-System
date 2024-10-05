package com.supply.dto;


import jakarta.validation.constraints.Email;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.validator.constraints.Length;

import java.io.Serializable;
import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserInformationDTO implements Serializable {

    private String username; //用户真实姓名

    private String firmName; //用户公司名

    @Email
    private String email; //用户邮箱

    @Length(max = 11)
    private String telephone; //用户电话

    private String password; //密码

    private List<String> verificationImages; //用户身份证明图片集

    private Integer identity; //注册用户身份，1为医护端，2为供应端

    private String verifyCode; //验证码

    @Length(max = 18)
    private String idNumber; //身份证号

}
