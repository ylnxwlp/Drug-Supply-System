package com.supply.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.time.LocalDateTime;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class MessageCache implements Serializable {

    private String content;

    private Long userId;

    private Long toUserId;

    private Boolean isInformation;

    private LocalDateTime sendTime;
}
