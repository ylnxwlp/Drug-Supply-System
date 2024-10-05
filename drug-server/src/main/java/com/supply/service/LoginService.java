package com.supply.service;

import com.supply.dto.UserInformationDTO;
import com.supply.dto.UserLoginDTO;
import com.supply.vo.UserLoginVO;
import org.springframework.stereotype.Service;

@Service
public interface LoginService {

    void register(UserInformationDTO userInformationDTO);

    void sendCode(String email, Long operationTpe);

    void resetPassword(UserInformationDTO userInformationDTO);

    UserLoginVO login(UserLoginDTO userLoginDTO);

    void logout();

    void ReUploadIdentityFile(UserInformationDTO userInformationDTO);
}
