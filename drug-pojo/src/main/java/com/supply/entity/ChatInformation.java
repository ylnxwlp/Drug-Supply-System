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
public class ChatInformation implements Serializable {

    private Long id;

    private Long queueId;

    private Long sendUserId;

    private Long receiveUserId;

    private String information;

    private String image;

    private LocalDateTime sendTime;
}
