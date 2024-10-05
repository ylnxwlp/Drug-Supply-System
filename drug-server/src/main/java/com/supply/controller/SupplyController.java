package com.supply.controller;

import com.supply.dto.DrugInformationDTO;
import com.supply.dto.DrugNumberChangeDTO;
import com.supply.dto.PageQueryDTO;
import com.supply.result.PageResult;
import com.supply.result.Result;
import com.supply.service.SupplyService;
import com.supply.vo.RequestVO;
import com.supply.vo.UserInformationVO;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Objects;

@RestController
@RequestMapping("/supply")
@Tag(name = "供应端部分接口")
@Slf4j
@RequiredArgsConstructor
public class SupplyController {

    private final SupplyService supplyService;

    @GetMapping("/information")
    @Operation(summary = "个人信息回显接口")
    @PreAuthorize("hasAuthority('supply:informtaion')")
    public Result<UserInformationVO> getInformation() {
        UserInformationVO userInformationVO = supplyService.getInformation();
        return Result.success(userInformationVO);
    }

    @GetMapping("/drugs")
    @Operation(summary = "药品信息查询接口")
    @PreAuthorize("hasAuthority('supply:getDrugs')")
    public Result<PageResult> getDrugsInformation(@RequestBody PageQueryDTO pageQueryDTO) {
        PageResult pageResult = supplyService.getDrugsInformation(pageQueryDTO);
        return Result.success(pageResult);
    }

    @PutMapping("/drugs/modify/{id}")
    @Operation(summary = "修改药品信息接口")
    public Result<Objects> modifyDrugsInformation(@PathVariable Long id, @RequestBody DrugInformationDTO drugInformationDTO) {
        supplyService.modifyDrugsInformation(id, drugInformationDTO);
        return Result.success();
    }

    @PutMapping("/drugs/number/{id}")
    @Operation(summary = "药品库存数量增减接口")
    @PreAuthorize("hasAuthority('supply:addNumber')")
    public Result<Objects> ModifyDrugsNumber(@PathVariable Long id, @RequestBody @Valid DrugNumberChangeDTO drugNumberChangeDTO) {
        supplyService.ModifyDrugsNumber(id, drugNumberChangeDTO);
        return Result.success();
    }

    @PostMapping("/drugs/add")
    @Operation(summary = "药品信息增加接口")
    @PreAuthorize("hasAuthority('supply:addDrugs')")
    public Result<Objects> addDrugs(@RequestBody DrugInformationDTO drugInformationDTO) {
        supplyService.addDrugs(drugInformationDTO);
        return Result.success();
    }

    @DeleteMapping("/drugs/delete/{id}")
    @Operation(summary = "药品信息删除接口")
    @PreAuthorize("hasAuthority('supply:deleteDrugs')")
    public Result<Objects> deleteDrug(@PathVariable Long id) {
        supplyService.deleteDrug(id);
        return Result.success();
    }

    @GetMapping("/request")
    @Operation(summary = "药品请求信息查询接口")
    @PreAuthorize("hasAuthority('supply:getRequests')")
    public Result<List<RequestVO>> getDrugRequestInformation() {
        List<RequestVO> list = supplyService.getDrugRequestInformation();
        return Result.success(list);
    }

    @PutMapping("/agree/{id}")
    @Operation(summary = "同意供应接口")
    @PreAuthorize("hasAuthority('supply:agree')")
    public Result<Object> dealRequest(@PathVariable Long id, @RequestParam Integer drugAgree) {
        supplyService.dealRequest(id, drugAgree);
        return Result.success();
    }
}
