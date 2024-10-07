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
public class Blacklist implements Serializable {

    private Long id;

    private Long userId;

    private Long blackUserId;

    private LocalDateTime blackTime;



}
