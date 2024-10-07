package com.supply.service;

import com.supply.dto.DrugInformationDTO;
import com.supply.dto.DrugNumberChangeDTO;
import com.supply.dto.PageQueryDTO;
import com.supply.result.PageResult;
import com.supply.vo.RequestVO;
import com.supply.vo.UserInformationVO;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public interface SupplyService {


    UserInformationVO getInformation();

    PageResult getDrugsInformation(PageQueryDTO pageQueryDTO);

    void modifyDrugsInformation(Long id, DrugInformationDTO drugInformationDTO);

    void ModifyDrugsNumber(Long id, DrugNumberChangeDTO drugNumberChangeDTO);

    void addDrugs(List<DrugInformationDTO> drugInformationDTO);

    void deleteDrug(List<Long> ids);

    List<RequestVO> getDrugRequestInformation();

    void dealRequest(Long id, Integer drugAgree);
}
