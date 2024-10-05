package com.supply.vo;


import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserInformationVO implements Serializable {

    private Long id;

    private String username; //用户真实姓名

    private String email; //用户邮箱

    private String image; //用户头像

    private String firmName; //用户公司名

    private Long accountStatus; //用户状态

}
