package com.supply.mapper;

import com.supply.entity.IdentityAuthentication;
import com.supply.entity.Report;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Update;

import java.time.LocalDateTime;
import java.util.List;

@Mapper
public interface AdminMapper {


    /**
     * 获取不同工种下所有未审核的信息
     *
     * @param type 工种
     * @return 所有未审核的信息
     */
    @Select("select * from identity_authentication where work_type = #{workType} and verifier_id is null and pass_time is null")
    List<IdentityAuthentication> getVerificationInformation(Long type);

    /**
     * 根据申请id获取申请人
     *
     * @param id 申请id
     * @return 申请人
     */
    @Select("select user_id from identity_authentication where id = #{id}")
    Long getApplyUser(Long id);

    /**
     * 审核成功
     *
     * @param id         申请id
     * @param verifierId 审核人id
     * @param now        当前时间
     */
    @Update("update identity_authentication set pass_time = #{now},verifier_id = #{verifierId} where id = #{id}")
    void checkSuccessfully(Long id, Long verifierId, LocalDateTime now);

    /**
     * 审核失败
     *
     * @param id         申请id
     * @param verifierId 审核人id
     */
    @Update("update identity_authentication set verifier_id = #{verifierId} where id = #{id}")
    void checkUnsuccessfully(Long id, Long verifierId);

    /**
     * 查询所有未处理的举报信息
     *
     * @return 所有未处理的举报信息
     */
    @Select("select * from report where report_status = 1")
    List<Report> getAllReportInformation();

    /**
     * 将举报信息改为已处理
     *
     * @param id 举报id
     */
    @Update("update report set report_status = 2 where id = #{id}")
    void dealReport(Long id);

    /**
     * 根据id查询举报信息
     *
     * @param id 举报id
     * @return 举报信息
     */
    @Select("select * from report where id = #{id}")
    Report getReportInformation(Long id);
}
