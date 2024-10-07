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
public class ChatQueuesVO implements Serializable {

    private Long id;

    private Long userId;//对方用户的id

    private String username;//对方用户真实姓名

    private String image;//对方用户头像

    private String firmName;//对方用户的公司名

    private String lastSendTime; //最后聊天时间

    private String message;//最后一条信息
}
