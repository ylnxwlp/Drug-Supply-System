package com.supply.service;


import com.supply.dto.ReportDTO;
import com.supply.dto.UserInformationDTO;
import com.supply.vo.BlacklistVO;
import com.supply.vo.UserInformationVO;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public interface CommonService {

    List<BlacklistVO> getBlacklistInformation();

    void removeBlacklist(List<Long> ids);

    void addBlacklist(Long id);

    void report(ReportDTO reportDTO);

    UserInformationVO getModificationInformation();

    void updateUserInformation(UserInformationDTO userInformationDTO);
}
