package com.supply.consumer;

import cn.hutool.core.date.DatePattern;
import cn.hutool.core.date.DateUtil;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.supply.entity.ChatInformation;
import com.supply.mapper.ChatMapper;
import com.supply.service.impl.ChatServiceImpl;
import com.supply.websocket.ChatEndPoint;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.amqp.rabbit.annotation.Exchange;
import org.springframework.amqp.rabbit.annotation.Queue;
import org.springframework.amqp.rabbit.annotation.QueueBinding;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Objects;

@Slf4j
@RequiredArgsConstructor
@Component
public class MessageConsumer {

    private final ChatServiceImpl chatService;

    private final ChatMapper chatMapper;

    private final RedisTemplate<Object, Object> redisTemplate;

    private final ChatEndPoint chatEndPoint;

    @RabbitListener(bindings = @QueueBinding(
            value = @Queue(name = "finish.queue"),
            exchange = @Exchange(name = "finish.direct"),
            key = {"finishDirect"}
    ))
    public void listenFinishQueue(String message) {
        log.info("接收到finish.queue的消息：{}", message + "," + DateUtil.format(LocalDateTime.now(), DatePattern.NORM_DATETIME_PATTERN));
        chatService.webSocketOnClose(message);
    }

    @RabbitListener(bindings = @QueueBinding(
            value = @Queue(name = "store.queue"),
            exchange = @Exchange(name = "store.direct"),
            key = {"storeDirect"}
    ))
    public void listenStoreQueue(String message) {
        log.info("接收到store.queue的消息：{}", message + ", " + DateUtil.format(LocalDateTime.now(), DatePattern.NORM_DATETIME_PATTERN));
        // 反序列化为 ChatInformation 对象
        try {
            ChatInformation chatInformation = JSON.parseObject(message, ChatInformation.class);
            // 将消息存储到数据库
            chatMapper.storeChatInformation(chatInformation);
            log.info("成功存储聊天信息：{}", chatInformation);
        } catch (Exception e) {
            log.error("反序列化消息失败，消息内容：{}，错误：{}", message, e.getMessage());
        }
    }

    @RabbitListener(bindings = @QueueBinding(
            value = @Queue(name = "message.queue"),
            exchange = @Exchange(name = "message.direct"),
            key = {"messageDirect"}
    ))
    public void listenMessageQueue(String message) {
        log.info("接收到message.queue的消息：{}", message + ", " + DateUtil.format(LocalDateTime.now(), DatePattern.NORM_DATETIME_PATTERN));
        Object o = redisTemplate.opsForValue().get("unReadMessage:" + message);
        if (!Objects.isNull(o)) {
            String json = o.toString();
            List<JSONObject> list = JSON.parseArray(json, JSONObject.class);
            for (JSONObject jsonObject : list) {
                Boolean isInformation = jsonObject.getBoolean("isInformation");
                Long toUserId = jsonObject.getLong("toUserId");
                Long userId = jsonObject.getLong("userId");
                String content = jsonObject.getString("content");
                LocalDateTime sendTime = LocalDateTime.parse(jsonObject.getString("sendTime"));
                chatEndPoint.sendMessageToUser(content,userId,toUserId,isInformation,sendTime);
                redisTemplate.delete("unReadMessage:" + message);
            }
        }
    }
}
