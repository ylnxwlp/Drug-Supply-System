package com.supply.service;

import com.supply.dto.ChatInformationDTO;
import com.supply.dto.ChatInformationSelectDTO;
import com.supply.vo.ChatInformationVO;
import com.supply.vo.ChatQueuesVO;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public interface ChatService {

    void createChatQueue(Long id);

    List<ChatQueuesVO> getChatQueues();

    List<ChatInformationVO> getChatHistoryInformation(Long id, Integer times);

    List<ChatInformationVO> selectChatInformationDuringAPeriod(Long id, ChatInformationSelectDTO chatInformationSelectDTO);

    List<ChatInformationVO> getChatInformation(Long id);

    void webSocketOnClose(String message);
}
