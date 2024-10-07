package com.supply.controller;

import com.supply.constant.MessageConstant;
import com.supply.dto.ReportDTO;
import com.supply.dto.UserInformationDTO;
import com.supply.result.Result;
import com.supply.service.CommonService;
import com.supply.utils.AliOssUtil;
import com.supply.vo.BlacklistVO;
import com.supply.vo.UserInformationVO;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;

@RestController
@RequestMapping("/common")
@Tag(name = "文件上传")
@Slf4j
@RequiredArgsConstructor
public class CommonController {

    private final AliOssUtil aliOssUtil;

    private final CommonService commonService;

    @PostMapping("/upload")
    @Operation(summary = "文件上传接口")
    public Result<String> upload(MultipartFile file) {
        log.info("文件上传：{}", file);
        try {
            String upload = aliOssUtil.upload(file);
            return Result.success(upload);
        } catch (IOException e) {
            log.error("文件上传失败:{}", e.getMessage());
        }
        return Result.error(MessageConstant.UPLOAD_FAILED);
    }

    @GetMapping("/blacklist")
    @Operation(summary = "黑名单信息查询接口")
    @PreAuthorize("hasAuthority('sys:blacklist')")
    public Result<List<BlacklistVO>> getBlacklistInformation() {
        List<BlacklistVO> list = commonService.getBlacklistInformation();
        return Result.success(list);
    }

    @DeleteMapping("/blacklist/remove")
    @Operation(summary = "移除黑名单信息接口")
    @PreAuthorize("hasAuthority('sys:removeBlacklist')")
    public Result<Object> removeBlacklist(List<Long> ids) {
        commonService.removeBlacklist(ids);
        return Result.success();
    }

    @DeleteMapping("/addBlacklist")
    @Operation(summary = "添加黑名单信息接口")
    @PreAuthorize("hasAuthority('sys:addBlacklist')")
    public Result<Object> addBlacklist(@RequestParam Long id) {
        commonService.addBlacklist(id);
        return Result.success();
    }

    @DeleteMapping("/report")
    @Operation(summary = "举报接口")
    @PreAuthorize("hasAuthority('sys:report')")
    public Result<Object> report(@RequestBody ReportDTO reportDTO) {
        commonService.report(reportDTO);
        return Result.success();
    }

    @GetMapping("modification/information")
    @Operation(summary = "编辑处个人信息回显接口")
    @PreAuthorize("hasAuthority('sys:myInformation')")
    public Result<UserInformationVO> getModificationInformation() {
        UserInformationVO userInformationVO = commonService.getModificationInformation();
        return Result.success(userInformationVO);
    }

    @GetMapping("/modification")
    @Operation(summary = "修改个人信息接口")
    @PreAuthorize("hasAuthority('sys:modifyMyInformation')")
    public Result<Object> updateInformation(@RequestBody UserInformationDTO userInformationDTO) {
        commonService.updateUserInformation(userInformationDTO);
        return Result.success();
    }
}
