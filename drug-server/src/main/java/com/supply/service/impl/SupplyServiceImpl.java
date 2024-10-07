package com.supply.service.impl;

import cn.hutool.core.date.DatePattern;
import cn.hutool.core.date.DateUtil;
import cn.hutool.core.util.RandomUtil;
import com.github.pagehelper.PageHelper;
import com.supply.dto.DrugInformationDTO;
import com.supply.dto.DrugNumberChangeDTO;
import com.supply.dto.PageQueryDTO;
import com.supply.entity.LoginUser;
import com.supply.entity.Request;
import com.supply.entity.SupplyDrug;
import com.supply.entity.User;
import com.supply.mapper.SupplyMapper;
import com.supply.mapper.UserMapper;
import com.supply.result.PageResult;
import com.supply.service.SupplyService;
import com.supply.vo.RequestVO;
import com.supply.vo.SupplyDrugVO;
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
public class SupplyServiceImpl implements SupplyService {

    private final SupplyMapper supplyMapper;

    private final UserMapper userMapper;

    private final RedisTemplate<Object, Object> redisTemplate;

    /**
     * 个人信息回显
     *
     * @return 用户信息
     */
    public UserInformationVO getInformation() {
        User user = userMapper.getUserInformationById(getCurrentUserId());
        UserInformationVO userInformationVO = new UserInformationVO();
        BeanUtils.copyProperties(user, userInformationVO);
        log.info("当前登录的供应端信息：{}", userInformationVO);
        return userInformationVO;
    }

    /**
     * 药品信息查询
     *
     * @return 药品所有信息
     */
    public PageResult getDrugsInformation(PageQueryDTO pageQueryDTO) {
        log.debug("查询{}页的数据，每页{}条", pageQueryDTO.getPage(), pageQueryDTO.getPageSize());
        Long userId = getCurrentUserId();
        List<SupplyDrugVO> list = null;
        try {
            list = (List<SupplyDrugVO>) redisTemplate.opsForValue().get("supply:drugs:" + userId);
        } catch (Exception e) {
            log.error("getDrugsInformation方法中redis反序列化异常");
        }
        if (list != null) {
            log.debug("该页面下药品信息为：{}", list);
            return new PageResult(list.size(), paginateList(list, pageQueryDTO.getPage(), pageQueryDTO.getPageSize()));
        }
        PageHelper.startPage(pageQueryDTO.getPage(), pageQueryDTO.getPageSize());
        List<SupplyDrug> drugs = supplyMapper.getDrugsInformation(userId);
        list = new ArrayList<>();
        if (drugs != null && !drugs.isEmpty()) {
            for (SupplyDrug drug : drugs) {
                SupplyDrugVO supplyDrugVO = new SupplyDrugVO();
                BeanUtils.copyProperties(drug, supplyDrugVO);
                supplyDrugVO.setLastModificationTime(DateUtil.format(drug.getUpdateTime(), DatePattern.NORM_DATETIME_PATTERN));
                log.info("当前药品信息为：{}", supplyDrugVO);
                list.add(supplyDrugVO);
            }
        }
        redisTemplate.opsForValue().set("supply:drugs:" + userId, list, 10 + RandomUtil.randomInt(10), TimeUnit.MINUTES);
        return new PageResult(list.size(), paginateList(list, pageQueryDTO.getPage(), pageQueryDTO.getPageSize()));
    }

    /**
     * 修改药品信息
     *
     * @param id                 药品id
     * @param drugInformationDTO 新药品信息
     */
    public void modifyDrugsInformation(Long id, DrugInformationDTO drugInformationDTO) {
        Long userId = getCurrentUserId();
        log.info("供应端修改药品信息：{}", drugInformationDTO);
        supplyMapper.modifyDrugsInformation(id, drugInformationDTO, LocalDateTime.now());
        redisTemplate.delete("supply:drugs:" + userId);
    }

    /**
     * 药品库存数量增减
     *
     * @param id                  药品id
     * @param drugNumberChangeDTO 药品增减信息
     */
    public void ModifyDrugsNumber(Long id, DrugNumberChangeDTO drugNumberChangeDTO) {
        Long userId = getCurrentUserId();
        Integer number;
        if (drugNumberChangeDTO.getAddOrSubtraction() == 1) {
            number = drugNumberChangeDTO.getNumber();
            log.info("对药品库存进行增操作，数量为：{}", number);
        } else {
            number = -1 * drugNumberChangeDTO.getNumber();
            log.info("对药品库存进行减操作，数量为：{}", number);
        }
        supplyMapper.ModifyDrugsNumber(id, number, LocalDateTime.now());
        redisTemplate.delete("supply:drugs:" + userId);
    }

    /**
     * 药品信息增加
     *
     * @param drugInformationDTOS 新药品信息
     */
    public void addDrugs(List<DrugInformationDTO> drugInformationDTOS) {
        Long userId = getCurrentUserId();
        log.info("当前供应端：{}增加药品信息：{}", userId, drugInformationDTOS);
        List<SupplyDrug> supplyDrugs = new ArrayList<>();
        for (DrugInformationDTO drugInformationDTO : drugInformationDTOS) {
            SupplyDrug supplyDrug = new SupplyDrug();
            BeanUtils.copyProperties(drugInformationDTO, supplyDrug);
            supplyDrug.setUpdateTime(LocalDateTime.now());
            supplyDrug.setUserId(getCurrentUserId());
            supplyDrugs.add(supplyDrug);
        }
        supplyMapper.addDrugs(supplyDrugs);
        redisTemplate.delete("supply:drugs:" + userId);
    }

    /**
     * 药品信息删除
     *
     * @param ids 药品id
     */
    public void deleteDrug(List<Long> ids) {
        Long userId = getCurrentUserId();
        log.info("当前供应端删除药品id：{}", ids);
        supplyMapper.deleteDrug(ids);
        redisTemplate.delete("supply:drugs:" + userId);
    }

    /**
     * 药品请求信息查询
     *
     * @return 药品请求信息
     */
    public List<RequestVO> getDrugRequestInformation() {
        Long userId = getCurrentUserId();
        List<RequestVO> list = null;
        try {
            list = (List<RequestVO>) redisTemplate.opsForValue().get("supply:request:" + userId);
        } catch (Exception e) {
            log.error("getDrugRequestInformation方法中redis反序列化异常");
        }
        if (list != null) {
            return list;
        }
        List<Request> requests = supplyMapper.getDrugRequestInformation(userId);
        list = new ArrayList<>();
        if (requests != null && !requests.isEmpty()) {
            for (Request request : requests) {
                RequestVO requestVO = new RequestVO();
                BeanUtils.copyProperties(request, requestVO);
                requestVO.setUserId(request.getRequestUserId());
                requestVO.setImage(userMapper.getUserInformationById(request.getRequestUserId()).getImage());
                requestVO.setUsername(userMapper.getUserInformationById(request.getRequestUserId()).getUsername());
                requestVO.setRequestTime(DateUtil.format(request.getRequestTime(), DatePattern.NORM_DATETIME_PATTERN));
                log.info("当前请求信息为：{}", requestVO);
                list.add(requestVO);
            }
        }
        redisTemplate.opsForValue().set("supply:request:" + userId, list, 5 + RandomUtil.randomInt(10), TimeUnit.MINUTES);
        return list;
    }

    /**
     * 处理药品请求接口
     *
     * @param id        请求id
     * @param drugAgree 是否同意，1为是，2为否
     */
    public void dealRequest(Long id, Integer drugAgree) {
        Long userId = getCurrentUserId();
        log.info("供应端对该次药品请求决定：{}", drugAgree);
        supplyMapper.dealRequest(id, drugAgree, LocalDateTime.now());
        redisTemplate.delete("supply:request:" + userId);
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
    private List<SupplyDrugVO> paginateList(List<SupplyDrugVO> list, int page, int pageSize) {
        int fromIndex = (page - 1) * pageSize;
        int toIndex = Math.min(fromIndex + pageSize, list.size());
        if (fromIndex >= list.size()) {
            return new ArrayList<>();
        }
        return list.subList(fromIndex, toIndex);
    }
}
