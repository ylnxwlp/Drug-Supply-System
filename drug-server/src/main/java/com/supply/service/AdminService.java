package com.supply.service;

import com.supply.vo.ReportInformationVO;
import com.supply.vo.UserInformationVO;
import com.supply.vo.VerificationInformationVO;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public interface AdminService {

    UserInformationVO getInformation();

    List<VerificationInformationVO> getVerificationInformation(Long type);

    void checkVerificationInformation(Long id, Long isAgree);

    List<ReportInformationVO> getReportInformation();

    void dealReport(Long id, Integer isIllegal,Integer isBlocked);

    List<UserInformationVO> getAllUsers();

    void block(Long id);

    void liftUser(Long id);
}
