package com.supply.mapper;

import com.supply.entity.ChatInformation;
import com.supply.entity.ChatQueue;
import org.apache.ibatis.annotations.Delete;
import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Select;

import java.time.LocalDateTime;
import java.util.List;

@Mapper
public interface ChatMapper {

    /**
     * 创建聊天队列
     *
     * @param currentId 当前发起聊天用户id
     * @param id        对方id
     * @param now       创建时间
     */
    @Insert("insert into chat_queue(user_id1, user_id2, create_time) VALUES(#{currentId},#{id},#{now}) ")
    void createChatQueue(Long currentId, Long id, LocalDateTime now);

    /**
     * 存储聊天数据
     *
     * @param chatInformation 聊天信息
     */
    @Insert("insert into chat_information(queue_id,information,image,send_user_id,receive_user_id,send_time) VALUES(#{queueId},#{information},#{image},#{sendUserId},#{receiveUserId},#{sendTime}) ")
    void storeChatInformation(ChatInformation chatInformation);

    /**
     * 获取当前用户参与的所有聊天队列
     *
     * @param currentId 当前用户id
     * @return 所有队列
     */
    @Select("select * from chat_queue where user_id1 = #{currentId} or user_id2 = #{currentId}")
    List<ChatQueue> getAllQueueByUserId(Long currentId);

    /**
     * 根据队列id获取一些聊天信息
     *
     * @param id 队列id
     * @return 所有聊天信息
     */
    @Select("select * from chat_information where queue_id = #{id} limit 5")
    List<ChatInformation> getChatInformationByQueueId(Long id);

    /**
     * 根据队列id删除队列
     *
     * @param id 队列id
     */
    @Delete("delete from chat_queue where id = #{id}")
    void deleteQueueById(Long id);

    /**
     * 根据队列id获取100条聊天信息
     *
     * @param id 当前用户id
     * @return 聊天信息
     */
    @Select("select * from chat_information where queue_id = #{id} order by send_time desc limit 75")
    List<ChatInformation> getRecentChatInformationByQueueId(Long id);


    /**
     * 查询聊天队列中的数据
     *
     * @param id   聊天队列id
     * @param from 从那一条数据开始获得
     * @param i    每一次获取多少数据
     * @return 聊天信息
     */
    @Select("select * from chat_information where queue_id = #{id} order by send_time desc limit #{from},#{i}")
    List<ChatInformation> getChatHistoryInformationByQueueIdAndTimes(Long id, Integer from, Integer i);

    /**
     * 查询指定时间内的聊天记录
     *
     * @param id        聊天队列id
     * @param beginTime 开始时间
     * @param endTime   结束时间
     * @return 聊天信息
     */
    @Select("select * from chat_information where queue_id = #{id} and send_time > #{beginTime} and send_time < #{endTime} order by send_time desc")
    List<ChatInformation> getChatInformationByQueueIdAndSendTime(Long id, LocalDateTime beginTime, LocalDateTime endTime);

    /**
     * 查询聊天队列中最后一条聊天记录
     *
     * @param id 聊天队列id
     * @return 最后一条聊天记录
     */
    @Select("select * from chat_information where id = #{id} order by send_time desc limit 1")
    ChatInformation getOneMessageByQueueId(Long id);

    /**
     * 根据聊天人获取聊天队列id
     *
     * @param userId   聊天人1
     * @param toUserId 聊天人2
     * @return 聊天队列id
     */
    @Select("select id from chat_queue where (user_id1 = #{userId} and user_id2 = #{toUserId}) or (user_id1 = #{toUserId} and user_id2 = #{userId})")
    Long getQueueByUserId(Long userId, Long toUserId);
}
