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
public class ChatInformationVO implements Serializable {

    private String lastSendTime; //该信息发送时间

    private String message;//信息内容

    private Integer sendPeople;//1为自己发送，2为对方发送
}
