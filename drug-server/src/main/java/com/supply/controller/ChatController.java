package com.supply.controller;

import com.supply.dto.ChatInformationDTO;
import com.supply.dto.ChatInformationSelectDTO;
import com.supply.result.Result;
import com.supply.service.ChatService;
import com.supply.vo.ChatInformationVO;
import com.supply.vo.ChatQueuesVO;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/message")
@Tag(name = "聊天信息处理类")
@RequiredArgsConstructor
public class ChatController {

    private final ChatService chatService;

    @PostMapping("/create")
    @Operation(summary = "创建聊天队列接口")
    public Result<Object> createChatQueue(@RequestParam Long id) {
        chatService.createChatQueue(id);
        return Result.success();
    }

    @GetMapping("/queues")
    @Operation(summary = "查询聊天队列接口")
    public Result<List<ChatQueuesVO>> getChatQueues() {
        List<ChatQueuesVO> list = chatService.getChatQueues();
        return Result.success(list);
    }

    @GetMapping("/queue/{id}")
    @Operation(summary = "查询聊天信息接口")
    public Result<List<ChatInformationVO>> getChatInformation(@PathVariable Long id) {
        List<ChatInformationVO> list = chatService.getChatInformation(id);
        return Result.success(list);
    }

    @GetMapping("/queue/history/{id}")
    @Operation(summary = "查询历史聊天信息接口")
    public Result<List<ChatInformationVO>> getChatHistoryInformation(@PathVariable Long id, @RequestParam Integer times) {
        List<ChatInformationVO> list = chatService.getChatHistoryInformation(id, times);
        return Result.success(list);
    }

    @GetMapping("/queue/time/{id}")
    @Operation(summary = "查询指定时间的聊天信息接口")
    public Result<List<ChatInformationVO>> selectChatInformationDuringAPeriod(@PathVariable Long id, @Valid @RequestBody ChatInformationSelectDTO chatInformationSelectDTO) {
        List<ChatInformationVO> list = chatService.selectChatInformationDuringAPeriod(id, chatInformationSelectDTO);
        return Result.success(list);
    }
}
