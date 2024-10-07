package com.supply.service.impl;


import cn.hutool.core.util.RandomUtil;
import com.supply.dto.ReportDTO;
import com.supply.dto.UserInformationDTO;
import com.supply.entity.Blacklist;
import com.supply.entity.LoginUser;
import com.supply.entity.Report;
import com.supply.entity.User;
import com.supply.mapper.CommonMapper;
import com.supply.mapper.UserMapper;
import com.supply.service.CommonService;
import com.supply.vo.BlacklistVO;
import com.supply.vo.UserInformationVO;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.BeanUtils;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

@Service
@Slf4j
@RequiredArgsConstructor
public class CommonServiceImpl implements CommonService {

    private final CommonMapper commonMapper;

    private final UserMapper userMapper;

    private final RedisTemplate<Object, Object> redisTemplate;

    /**
     * 查询黑名单
     *
     * @return 黑名单信息
     */
    public List<BlacklistVO> getBlacklistInformation() {
        Long userId = getCurrentUserId();
        List<BlacklistVO> list = null;
        try {
            list = (List<BlacklistVO>) redisTemplate.opsForValue().get("blacklist:" + userId);
        } catch (Exception e) {
            log.error("getBlacklistInformation方法中出现redis反序列化异常");
        }
        if (list != null) {
            return list;
        }
        List<Blacklist> blacklists = commonMapper.getBlacklistInformation(userId);
        list = new ArrayList<>();
        if (blacklists != null && !blacklists.isEmpty()) {
            for (Blacklist blacklist : blacklists) {
                BlacklistVO blacklistVO = new BlacklistVO();
                BeanUtils.copyProperties(blacklist, blacklistVO);
                User blackUserInformation = userMapper.getUserInformationById(blacklist.getBlackUserId());
                blacklistVO.setUsername(blackUserInformation.getUsername());
                blacklistVO.setImage(blackUserInformation.getImage());
                blacklistVO.setFirmName(blackUserInformation.getFirmName());
                list.add(blacklistVO);
            }
            redisTemplate.opsForValue().set("blacklist:" + userId, list, 23 + RandomUtil.randomInt(2), TimeUnit.HOURS);
        }
        return list;
    }

    /**
     * 根据黑名单id删除黑名单信息
     *
     * @param ids 黑名单id
     */
    public void removeBlacklist(List<Long> ids) {
        commonMapper.removeBlacklist(ids);
    }

    /**
     * 增加黑名单
     *
     * @param id 拉黑的用户id
     */
    public void addBlacklist(Long id) {
        Long userId = getCurrentUserId();
        commonMapper.addBlacklist(userId, id, LocalDateTime.now());
        redisTemplate.delete("blacklist:" + userId);
    }

    /**
     * 举报
     */
    public void report(ReportDTO reportDTO) {
        Long userId = getCurrentUserId();
        Report report = new Report();
        BeanUtils.copyProperties(reportDTO, report);
        List<String> images = reportDTO.getImages();
        report.setImages(String.join(",", images));
        report.setReportTime(LocalDateTime.now());
        report.setIdentity(userMapper.getUserInformationById(report.getId()).getWorkType());
        report.setReporterIdentity(userMapper.getUserInformationById(userId).getWorkType());
        report.setUserId(reportDTO.getId());
        report.setReportUserId(userId);
        commonMapper.report(report);
        redisTemplate.delete("report");
    }

    /**
     * 修改个人信息回显
     *
     * @return 个人信息
     */
    public UserInformationVO getModificationInformation() {
        Long userId = getCurrentUserId();
        User user = userMapper.getUserInformationById(userId);
        UserInformationVO userInformationVO = new UserInformationVO();
        BeanUtils.copyProperties(user, userInformationVO);
        return userInformationVO;
    }


    /**
     * 修改个人信息
     *
     * @param userInformationDTO 新信息
     */
    public void updateUserInformation(UserInformationDTO userInformationDTO) {
        Long userId = getCurrentUserId();
        log.info("修改用户个人信息：{}", userInformationDTO);
        new User();
        User user = User.builder()
                .id(userId)
                .firmName(userInformationDTO.getFirmName())
                .email(userInformationDTO.getEmail())
                .telephone(userInformationDTO.getTelephone())
                .updateTime(LocalDateTime.now())
                .build();
        commonMapper.updateUserInformation(user);
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
