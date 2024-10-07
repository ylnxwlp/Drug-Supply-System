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
public class ChatQueue implements Serializable {

    private Long id;

    private Long userId1;

    private Long userId2;

    private LocalDateTime createTime;
}
