package com.supply.mapper;


import com.supply.dto.DrugInformationDTO;
import com.supply.entity.Request;
import com.supply.entity.SupplyDrug;
import org.apache.ibatis.annotations.*;

import java.time.LocalDateTime;
import java.util.List;

@Mapper
public interface SupplyMapper {


    /**
     * 根据用户id获取所属所有药品信息
     *
     * @param id 用户id
     * @return 药品信息
     */
    @Select("select * from supply_drug where user_id = #{id}")
    List<SupplyDrug> getDrugsInformation(Long id);

    /**
     * 修改药品信息
     *
     * @param id                 药品id
     * @param drugInformationDTO 新药品信息
     * @param now                当前修改时间
     */
    @Update("update supply_drug set drug_name = #{drugName} and inventory_number = #{inventoryNumber} and update_time = #{now} where id = #{id}")
    void modifyDrugsInformation(Long id, DrugInformationDTO drugInformationDTO, LocalDateTime now);

    /**
     * 药品库存数量增减
     *
     * @param id     药品id
     * @param number 药品增减数量
     * @param now    当前修改时间
     */
    @Update("update supply_drug set inventory_number = inventory_number + #{number} and update_time = #{now} where id = #{id}")
    void ModifyDrugsNumber(Long id, Integer number, LocalDateTime now);

    /**
     * 药品信息增加
     *
     * @param supplyDrug 新药品信息
     */

    void addDrugs(List<SupplyDrug> supplyDrug);

    /**
     * 药品信息删除
     *
     * @param ids 药品id
     */
    void deleteDrug(List<Long> ids);

    /**
     * 药品请求信息查询
     *
     * @param id 用户id
     * @return 药品请求信息
     */
    @Select("select * from request where user_id = #{id} and isAgree is null and response_time is null ")
    List<Request> getDrugRequestInformation(Long id);

    /**
     * @param id        请求id
     * @param drugAgree 是否同意
     * @param now       响应时间
     */
    @Update("update request set isAgree = #{drugAgree} and response_time = #{now} where id = #{id}")
    void dealRequest(Long id, Integer drugAgree, LocalDateTime now);
}
