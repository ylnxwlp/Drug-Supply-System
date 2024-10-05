package com.supply.service.impl;

import cn.hutool.core.date.DatePattern;
import cn.hutool.core.date.DateUtil;
import com.supply.entity.*;
import com.supply.mapper.AdminMapper;
import com.supply.mapper.UserMapper;
import com.supply.service.AdminService;
import com.supply.utils.EmailUtil;
import com.supply.vo.ReportInformationVO;
import com.supply.vo.UserInformationVO;
import com.supply.vo.VerificationInformationVO;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.BeanUtils;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

@Service
@Slf4j
@RequiredArgsConstructor
public class AdminServiceImpl implements AdminService {

    private final AdminMapper adminMapper;

    private final UserMapper userMapper;

    private final EmailUtil emailUtil;

    private final RedisTemplate<Object, Object> redisTemplate;

    /**
     * 个人信息回显
     *
     * @return 用户信息
     */
    public UserInformationVO getInformation() {
        Long userId = getCurrentUserId();
        User user = userMapper.getUserInformationById(userId);
        UserInformationVO userInformationVO = new UserInformationVO();
        BeanUtils.copyProperties(user, userInformationVO);
        log.debug("当前登录的管理员信息：{}", userInformationVO);
        return userInformationVO;
    }

    /**
     * 申请认证信息查询
     *
     * @param type 工种编号，1为医护端，2为供应端
     * @return 待审核的身份信息
     */
    public List<VerificationInformationVO> getVerificationInformation(Long type) {
        String cacheKey = "VerificationInformation:" + type;
        List<VerificationInformationVO> list = null;
        try {
            list = (List<VerificationInformationVO>) redisTemplate.opsForValue().get(cacheKey);
        } catch (Exception e) {
            log.error("getVerificationInformation方法中redis反序列化异常");
        }
        if (list != null) {
            return list;
        }
        List<IdentityAuthentication> verificationInformation = adminMapper.getVerificationInformation(type);
        log.debug("工种编号为{}的申请信息：{}", type, verificationInformation);
        list = verificationInformation.stream().map(info -> {
            VerificationInformationVO vo = new VerificationInformationVO();
            BeanUtils.copyProperties(info, vo);
            vo.setApplicationTime(DateUtil.format(info.getApplicationTime(), DatePattern.NORM_DATETIME_PATTERN));
            User user = userMapper.getUserInformationById(info.getUserId());
            vo.setUsername(user.getUsername());
            vo.setFirmName(user.getFirmName());
            vo.setImages(Arrays.asList(info.getImages().split(",")));
            log.debug("查询到的数据信息：{}", vo);
            return vo;
        }).collect(Collectors.toList());
        if (!list.isEmpty()) {
            redisTemplate.opsForValue().set(cacheKey, list, 1, TimeUnit.HOURS);
        } else {
            log.debug("工种编号{}下暂时没有新的申请信息", type);
        }
        return list;
    }

    /**
     * 身份信息审核接口
     *
     * @param id      身份信息申请id
     * @param isAgree 是否同意，1为是，2为否
     */
    @Transactional
    public void checkVerificationInformation(Long id, Long isAgree) {
        log.debug("管理员对于申请编号为{}的认证做出决定：{}", id, isAgree);
        Long applyUserId = adminMapper.getApplyUser(id);
        User applyUserInformation = userMapper.getUserInformationById(applyUserId);
        String email = applyUserInformation.getEmail();
        Long adminId = getCurrentUserId();
        if (isAgree == 1) {
            userMapper.changeStatusToNormal(applyUserId, LocalDateTime.now());
            adminMapper.checkSuccessfully(id, adminId, LocalDateTime.now());
            userMapper.setAuthority(applyUserId, applyUserInformation.getWorkType());
            redisTemplate.delete("allUsers");
            emailUtil.normalMail(email, String.format("你的账户信息审核已通过，立即可用。审核人编号：%d", adminId));
        } else {
            userMapper.changeStatusToCheckFailed(applyUserId, LocalDateTime.now());
            adminMapper.checkUnsuccessfully(id, adminId);
            emailUtil.normalMail(email, String.format("你的账户信息审核未通过，请重新提交。审核人编号：%d", adminId));
        }
    }

    /**
     * 举报信息查询接口
     *
     * @return 举报信息
     */
    public List<ReportInformationVO> getReportInformation() {
        List<ReportInformationVO> list = null;
        try {
            list = (List<ReportInformationVO>) redisTemplate.opsForValue().get("report");
        } catch (Exception e) {
            log.error("getReportInformation方法中redis反序列化异常");
        }
        if (list != null) {
            return list;
        }
        log.debug("查询所有举报信息");
        List<Report> reports = adminMapper.getAllReportInformation();
        list = reports.stream().map(report -> {
            ReportInformationVO vo = new ReportInformationVO();
            BeanUtils.copyProperties(report, vo);
            vo.setReportTime(DateUtil.format(report.getReportTime(), DatePattern.NORM_DATETIME_PATTERN));
            vo.setImages(Arrays.asList(report.getImages().split(",")));
            vo.setFirmName(userMapper.getUserInformationById(report.getUserId()).getFirmName());
            vo.setInformerFirmName(userMapper.getUserInformationById(report.getReportUserId()).getFirmName());
            return vo;
        }).collect(Collectors.toList());

        if (!list.isEmpty()) {
            redisTemplate.opsForValue().set("report", list, 3, TimeUnit.HOURS);
        }
        return list;
    }

    /**
     * 处理举报信息
     *
     * @param id        举报id
     * @param isIllegal 是否违规，1为是，2为否
     * @param isBlocked 是否进行封禁处理
     */
    @Transactional
    public void dealReport(Long id, Integer isIllegal, Integer isBlocked) {
        log.debug("管理员处理举报id：{}，违规标志：{}", id, isIllegal);
        Report report = adminMapper.getReportInformation(id);
        String reportUserEmail = userMapper.getUserInformationById(report.getReportUserId()).getEmail();
        String userEmail = userMapper.getUserInformationById(report.getUserId()).getEmail();
        adminMapper.dealReport(id);
        if (isIllegal == 1 && isBlocked == 2) {
            emailUtil.normalMail(reportUserEmail, """
                    你好，
                    经过我们的核实，发现你的举报对象确实存在违规行为，因而举报成立。
                    我们已对其进行警告，并将持续关注，若发现其仍有违反规定的行为，将采取封号措施，感谢你对供应系统做出的贡献。""");
            emailUtil.normalMail(userEmail, """
                    你好，
                    你已被举报。经过我们的核实，发现你的账号确实存在违规行为。
                    如果仍有违规行为，我们可能对你的账号进行封号处理，如有异议，请联系管理人员。""");
        } else if (isIllegal == 1 && isBlocked == 1) {
            //将被举报人的账户封禁
            userMapper.blockAccount(report.getUserId(),LocalDateTime.now());
            //向举报人发送邮件告知举报成功
            emailUtil.normalMail(reportUserEmail, """
                    你好，
                    经过我们的核实，发现你的举报对象确实存在违规行为，因而举报成立。
                    我们已对其采取封号措施，感谢你对供应系统做出的贡献。""");
            //再向被举报人发送邮件
            emailUtil.normalMail(userEmail, """
                    你好，
                    你已被举报。经过我们的核实，发现你的账号确实存在违规行为。
                    我们已对你的账号进行封号处理，如有异议请联系管理人员。""");
        } else {
            emailUtil.normalMail(reportUserEmail, """
                    你好，
                    经过我们的核实，发现你的举报对象暂时不存在违规行为，因而举报不成立。
                    我们将持续关注，若发现其有违反规定的行为，将采取警告或封号措施，感谢你对供应系统做出的贡献。""");
        }
    }

    /**
     * 获取所有通过认证的用户信息
     *
     * @return 用户信息
     */
    public List<UserInformationVO> getAllUsers() {
        List<UserInformationVO> list = null;
        try {
            list = (List<UserInformationVO>) redisTemplate.opsForValue().get("allUsers");
        } catch (Exception e) {
            log.error("getAllUsers方法中redis反序列化异常");
        }
        if (list != null) {
            log.debug("缓存中的用户信息：{}", list);
            return list;
        }
        log.debug("查询所有用户信息");
        List<User> users = userMapper.getAllUsers();
        list = users.stream().map(user -> {
            UserInformationVO vo = new UserInformationVO();
            BeanUtils.copyProperties(user, vo);
            return vo;
        }).collect(Collectors.toList());
        if (!list.isEmpty()) {
            redisTemplate.opsForValue().set("allUsers", list, 30, TimeUnit.MINUTES);
        }
        return list;
    }

    /**
     * 封禁用户
     * @param id 用户id
     */
    public void block(Long id) {
        userMapper.blockAccount(id,LocalDateTime.now());
    }

    /**
     * 解封用户
     * @param id 用户id
     */
    public void liftUser(Long id) {
        userMapper.liftUser(id,LocalDateTime.now());
    }

    /**
     * 获取当前登录用户的ID
     */
    private Long getCurrentUserId() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        LoginUser loginUser = (LoginUser) authentication.getPrincipal();
        return loginUser.getUser().getId();
    }
}
