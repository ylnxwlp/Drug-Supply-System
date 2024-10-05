package com.supply.service.impl;

import cn.hutool.core.date.DatePattern;
import cn.hutool.core.date.DateUtil;
import cn.hutool.core.util.RandomUtil;
import com.alibaba.fastjson.JSON;
import com.supply.dto.PageQueryDTO;
import com.supply.entity.*;
import com.supply.enumeration.EmailType;
import com.supply.mapper.AdminMapper;
import com.supply.mapper.UserMapper;
import com.supply.result.PageResult;
import com.supply.service.AdminService;
import com.supply.vo.ReportInformationVO;
import com.supply.vo.UserInformationVO;
import com.supply.vo.VerificationInformationVO;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.amqp.rabbit.connection.CorrelationData;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
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

    private final RedisTemplate<Object, Object> redisTemplate;

    private final RabbitTemplate rabbitTemplate;

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
            redisTemplate.opsForValue().set(cacheKey, list, 55 + RandomUtil.randomInt(10), TimeUnit.MINUTES);
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
            String jsonString = JSON.toJSONString(EmailMessage.builder()
                    .emailAddress(email)
                    .emailType(EmailType.CHECK_SUCCESS.toString())
                    .adminId(adminId)
                    .build());
            CorrelationData correlationData = new CorrelationData(UUID.randomUUID().toString());
            rabbitTemplate.convertAndSend("email.direct", "emailDirect", jsonString, correlationData);
        } else {
            userMapper.changeStatusToCheckFailed(applyUserId, LocalDateTime.now());
            adminMapper.checkUnsuccessfully(id, adminId);
        }
        redisTemplate.delete("VerificationInformation:" + applyUserInformation.getWorkType());
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
            redisTemplate.opsForValue().set("report", list, 175 + RandomUtil.randomInt(10), TimeUnit.MINUTES);
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
    public void dealReport(Long id, Integer isIllegal, Integer isBlocked) {
        log.debug("管理员处理举报id：{}，违规标志：{}", id, isIllegal);
        Report report = adminMapper.getReportInformation(id);
        String reportUserEmail = userMapper.getUserInformationById(report.getReportUserId()).getEmail();
        String userEmail = userMapper.getUserInformationById(report.getUserId()).getEmail();
        adminMapper.dealReport(id);
        if (isIllegal == 1 && isBlocked == 2) {
            //向mq发送消息
            String jsonString = JSON.toJSONString(EmailMessage.builder()
                    .emailAddress(reportUserEmail)
                    .anotherEmailAddress(userEmail)
                    .emailType(EmailType.REPORT_BLOCKED.toString()));
            CorrelationData correlationData = new CorrelationData(UUID.randomUUID().toString());
            rabbitTemplate.convertAndSend("email.direct", "emailDirect", jsonString, correlationData);
        } else if (isIllegal == 1 && isBlocked == 1) {
            //将被举报人的账户封禁
            userMapper.blockAccount(report.getUserId(), LocalDateTime.now());
            //向mq发送消息
            String jsonString = JSON.toJSONString(EmailMessage.builder()
                    .emailAddress(reportUserEmail)
                    .anotherEmailAddress(userEmail)
                    .emailType(EmailType.REPORT_BLOCKED.toString()));
            CorrelationData correlationData = new CorrelationData(UUID.randomUUID().toString());
            rabbitTemplate.convertAndSend("email.direct", "emailDirect", jsonString, correlationData);
        } else {
            //向mq发送消息
            String jsonString = JSON.toJSONString(EmailMessage.builder()
                    .emailAddress(reportUserEmail)
                    .emailType(EmailType.REPORT_BLOCKED.toString()));
            CorrelationData correlationData = new CorrelationData(UUID.randomUUID().toString());
            rabbitTemplate.convertAndSend("email.direct", "emailDirect", jsonString, correlationData);
        }
        redisTemplate.delete("report");
    }

    /**
     * 获取所有通过认证的用户信息
     *
     * @return 用户信息
     */
    public PageResult getAllUsers(PageQueryDTO pageQueryDTO) {
        List<UserInformationVO> list = null;
        try {
            list = (List<UserInformationVO>) redisTemplate.opsForValue().get("allUsers");
        } catch (Exception e) {
            log.error("getAllUsers方法中redis反序列化异常");
        }
        if (list != null) {
            log.debug("缓存中的用户信息：{}", list);
            return new PageResult(list.size(), paginateList(list, pageQueryDTO.getPage(), pageQueryDTO.getPageSize()));
        }
        log.debug("查询所有用户信息");
        List<User> users = userMapper.getAllUsers();
        list = users.stream().map(user -> {
            UserInformationVO vo = new UserInformationVO();
            BeanUtils.copyProperties(user, vo);
            return vo;
        }).collect(Collectors.toList());
        if (!list.isEmpty()) {
            redisTemplate.opsForValue().set("allUsers", list, 25 + RandomUtil.randomInt(10), TimeUnit.MINUTES);
        }
        return new PageResult(list.size(), paginateList(list, pageQueryDTO.getPage(), pageQueryDTO.getPageSize()));
    }

    /**
     * 封禁用户
     *
     * @param id 用户id
     */
    public void block(Long id) {
        userMapper.blockAccount(id, LocalDateTime.now());
    }

    /**
     * 解封用户
     *
     * @param id 用户id
     */
    public void liftUser(Long id) {
        userMapper.liftUser(id, LocalDateTime.now());
    }

    /**
     * 获取当前登录用户的ID
     */
    private Long getCurrentUserId() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        LoginUser loginUser = (LoginUser) authentication.getPrincipal();
        return loginUser.getUser().getId();
    }

    /**
     * 分页查询截取
     *
     * @param list     截取集合
     * @param page     起始页面
     * @param pageSize 页面数据数
     * @return 截取后的集合
     */
    private List<UserInformationVO> paginateList(List<UserInformationVO> list, int page, int pageSize) {
        int fromIndex = (page - 1) * pageSize;
        int toIndex = Math.min(fromIndex + pageSize, list.size());
        if (fromIndex >= list.size()) {
            return new ArrayList<>();
        }
        return list.subList(fromIndex, toIndex);
    }
}
