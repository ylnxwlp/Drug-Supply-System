package com.supply.vo;


import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class BlacklistVO implements Serializable {

    private Long id;

    private Long blackUserId;//拉黑用户的id

    private String username;//拉黑用户真实姓名

    private String image;//拉黑用户头像

    private String firmName;//拉黑用户的公司名

    private String blackTime; //拉黑时间
}
