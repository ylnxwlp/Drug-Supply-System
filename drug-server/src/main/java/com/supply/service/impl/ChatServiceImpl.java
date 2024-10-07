package com.supply.service.impl;

import cn.hutool.core.date.DatePattern;
import cn.hutool.core.date.DateUtil;
import cn.hutool.core.util.RandomUtil;
import com.supply.dto.ChatInformationSelectDTO;
import com.supply.entity.ChatInformation;
import com.supply.entity.ChatQueue;
import com.supply.entity.LoginUser;
import com.supply.entity.User;
import com.supply.mapper.ChatMapper;
import com.supply.mapper.UserMapper;
import com.supply.service.ChatService;
import com.supply.vo.ChatInformationVO;
import com.supply.vo.ChatQueuesVO;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
@Slf4j
public class ChatServiceImpl implements ChatService {

    private final ChatMapper chatMapper;

    private final UserMapper userMapper;

    private final RedisTemplate<Object, Object> redisTemplate;

    /**
     * 创建聊天队列
     *
     * @param id 对方聊天人id
     */
    public void createChatQueue(Long id) {
        Long userId = getCurrentUserId();
        chatMapper.createChatQueue(userId, id, LocalDateTime.now());
    }

    /**
     * 获取所有队列的聊天信息
     *
     * @return 所有聊天队列信息
     */
    public List<ChatQueuesVO> getChatQueues() {
        Long id = getCurrentUserId();
        List<ChatQueue> queues = chatMapper.getAllQueueByUserId(id);
        log.info("当前用户所有聊天队列：{}", queues);
        List<ChatQueuesVO> list = new ArrayList<>();
        if (queues != null && !queues.isEmpty()) {
            for (ChatQueue queue : queues) {
                ChatQueuesVO chatQueuesVO = new ChatQueuesVO();
                chatQueuesVO.setId(queue.getId());
                if (Objects.equals(queue.getUserId1(), id)) {
                    chatQueuesVO.setUserId(queue.getUserId2());
                } else {
                    chatQueuesVO.setUserId(queue.getUserId1());
                }
                User userInformation = userMapper.getUserInformationById(chatQueuesVO.getUserId());
                chatQueuesVO.setFirmName(userInformation.getFirmName());
                chatQueuesVO.setImage(userInformation.getImage());
                ChatInformation chatInformation = chatMapper.getOneMessageByQueueId(queue.getId());
                if (chatInformation.getInformation() != null) {
                    chatQueuesVO.setMessage(chatInformation.getInformation());
                } else {
                    chatQueuesVO.setMessage("[图片]");
                }
                chatQueuesVO.setUsername(userInformation.getUsername());
                chatQueuesVO.setLastSendTime(DateUtil.format(chatInformation.getSendTime(), DatePattern.NORM_DATETIME_PATTERN));
                list.add(chatQueuesVO);
            }
            log.info("当前用户所有聊天队列信息：{}", list);
        }
        return list;
    }


    /**
     * 获取最近的聊天信息
     *
     * @param id 聊天队列id
     * @return 聊天信息
     */
    public List<ChatInformationVO> getChatInformation(Long id) {
        List<ChatInformationVO> list = null;
        try {
            list = (List<ChatInformationVO>) redisTemplate.opsForValue().get("queue:" + id);
        } catch (Exception e) {
            log.error("getChatInformation方法中出现redis反序列化异常");
        }
        if (list != null) {
            return list;
        }
        List<ChatInformation> information = chatMapper.getRecentChatInformationByQueueId(id);
        list = packChatInformation(information);
        redisTemplate.opsForValue().set("queue:" + id, list, 30 + RandomUtil.randomInt(5), TimeUnit.MINUTES);
        return list;
    }

    /**
     * 获取聊天信息
     *
     * @param id    聊天队列id
     * @param times 获取前多少次的聊天记录，默认从1开始
     * @return 聊天信息
     */
    public List<ChatInformationVO> getChatHistoryInformation(Long id, Integer times) {
        log.debug("开始获取id为{}聊天队列的前{}次的聊天记录", id, times);
        Integer from = (times - 1) * 100;
        List<ChatInformation> information = chatMapper.getChatHistoryInformationByQueueIdAndTimes(id, from, 100);
        return packChatInformation(information);
    }

    /**
     * 查询指定时间内的聊天信息
     *
     * @param id                       聊天队列id
     * @param chatInformationSelectDTO 指定时间
     * @return 聊天信息
     */
    public List<ChatInformationVO> selectChatInformationDuringAPeriod(Long id, ChatInformationSelectDTO chatInformationSelectDTO) {
        log.debug("开始获取id为{}聊天队列的从{}到{}的聊天记录", id, chatInformationSelectDTO.getBeginTime(), chatInformationSelectDTO.getEndTime());
        List<ChatInformationVO> list = null;
        try {
            list = (List<ChatInformationVO>) redisTemplate.opsForValue().get("chatInformationAboutTime:" + id + chatInformationSelectDTO.getBeginTime() + chatInformationSelectDTO.getEndTime());
        } catch (Exception e) {
            log.error("selectChatInformationDuringAPeriod方法中redis反序列化异常");
        }
        if (list != null) {
            log.info("聊天记录为：{}", list);
            return list;
        }
        LocalDateTime beginTime = LocalDateTime.parse(chatInformationSelectDTO.getBeginTime());
        LocalDateTime endTime = LocalDateTime.parse(chatInformationSelectDTO.getEndTime());
        List<ChatInformation> information = chatMapper.getChatInformationByQueueIdAndSendTime(id, beginTime, endTime);
        list = packChatInformation(information);
        redisTemplate.opsForValue().set("chatInformationAboutTime:" + id + chatInformationSelectDTO.getBeginTime() + chatInformationSelectDTO.getEndTime(),
                list, 1, TimeUnit.DAYS);
        log.info("聊天记录为：{}", list);
        return list;
    }


    /**
     * 聊天消息返还前端的包装方法
     *
     * @param information 聊天信息
     * @return 包装后的聊天信息
     */
    private List<ChatInformationVO> packChatInformation(List<ChatInformation> information) {
        Long userId = getCurrentUserId();
        List<ChatInformationVO> list = new ArrayList<>();
        if (information != null && !information.isEmpty()) {
            for (ChatInformation chatInformation : information) {
                ChatInformationVO chatInformationVO = new ChatInformationVO();
                if (chatInformation.getInformation() != null) {
                    chatInformationVO.setMessage(chatInformation.getInformation());
                } else {
                    chatInformationVO.setMessage(chatInformation.getImage());
                }
                if (Objects.equals(chatInformation.getSendUserId(), userId)) {
                    chatInformationVO.setSendPeople(1);
                } else {
                    chatInformationVO.setSendPeople(2);
                }
                chatInformationVO.setLastSendTime(DateUtil.format(chatInformation.getSendTime(), DatePattern.NORM_DATETIME_PATTERN));
                list.add(chatInformationVO);
            }
        }
        return list;
    }

    @Transactional
    public void webSocketOnClose(String message) {
        //对所有没有聊天的队列进行删除
        List<ChatQueue> chatQueues = chatMapper.getAllQueueByUserId(Long.valueOf(message));
        for (ChatQueue chatQueue : chatQueues) {
            List<ChatInformation> chatInformation = chatMapper.getChatInformationByQueueId(chatQueue.getId());
            if (chatInformation == null || chatInformation.isEmpty()) {
                chatMapper.deleteQueueById(chatQueue.getId());
            }
        }
    }

    /**
     * 获取当前登录用户的ID
     */
    private Long getCurrentUserId() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        LoginUser loginUser = (LoginUser) authentication.getPrincipal();
        return loginUser.getUser().getId();
    }
}
