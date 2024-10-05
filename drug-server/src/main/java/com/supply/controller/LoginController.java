package com.supply.controller;

import com.supply.dto.UserLoginDTO;
import com.supply.service.LoginService;
import com.supply.dto.UserInformationDTO;
import com.supply.vo.UserLoginVO;
import io.swagger.v3.oas.annotations.Operation;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;
import com.supply.result.Result;

@RestController
@RequiredArgsConstructor
@RequestMapping("/user")
public class LoginController {

    private final LoginService loginService;

    @PostMapping("/register")
    @Operation(summary = "用户注册接口")
    public Result<Object> register(@RequestBody UserInformationDTO userInformationDTO) {
        loginService.register(userInformationDTO);
        return Result.success();
    }

    @PostMapping("/verifyCode/send")
    @Operation(summary = "验证码发送接口")
    public Result<Object> sendCode(@RequestParam String email, @RequestParam Long operationType) {
        loginService.sendCode(email, operationType);
        return Result.success();
    }

    @PutMapping("/resetPassword")
    @Operation(summary = "重置密码接口")
    public Result<Object> resetPassword(@RequestBody @Valid UserInformationDTO userInformationDTO) {
        loginService.resetPassword(userInformationDTO);
        return Result.success();
    }

    @PostMapping("/login")
    @Operation(summary = "用户登录接口")
    public Result<UserLoginVO> login(@RequestBody @Valid UserLoginDTO userLoginDTO) {
        UserLoginVO userLoginVO = loginService.login(userLoginDTO);
        return Result.success(userLoginVO);
    }

    @PostMapping("/logout")
    @Operation(summary = "登出接口")
    public Result<Object> logout() {
        loginService.logout();
        return Result.success();
    }

    @PostMapping("/reUpload")
    @Operation(summary = "重新上传身份文件接口")
    public Result<Object> ReUploadIdentityFile(@RequestBody UserInformationDTO userInformationDTO) {
        loginService.ReUploadIdentityFile(userInformationDTO);
        return Result.success();
    }
}
