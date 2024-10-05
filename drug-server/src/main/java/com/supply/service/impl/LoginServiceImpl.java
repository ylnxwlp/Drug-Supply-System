package com.supply.service.impl;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.supply.constant.JwtClaimsConstant;
import com.supply.dto.UserLoginDTO;
import com.supply.entity.EmailMessage;
import com.supply.entity.LoginUser;
import com.supply.enumeration.EmailType;
import com.supply.exception.AccountStatusException;
import com.supply.exception.LoginErrorException;
import com.supply.mapper.UserMapper;
import com.supply.properties.JwtProperties;
import com.supply.service.LoginService;
import com.supply.dto.UserInformationDTO;
import com.supply.entity.IdentityAuthentication;
import com.supply.entity.User;
import com.supply.utils.JwtUtil;
import com.supply.vo.UserLoginVO;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.springframework.amqp.rabbit.connection.CorrelationData;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.supply.constant.MessageConstant;
import com.supply.exception.VerificationCodeErrorException;
import com.supply.utils.EmailUtil;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
@Slf4j
public class LoginServiceImpl implements LoginService {

    private final RedisTemplate<Object, Object> redisTemplate;

    private final UserMapper userMapper;

    private final BCryptPasswordEncoder passwordEncoder;

    private final EmailUtil emailUtil;

    private final AuthenticationConfiguration authenticationConfiguration;

    private final JwtProperties jwtProperties;

    private final RabbitTemplate rabbitTemplate;

    @Value("${drug.locationKey.key}")
    private String key;

    /**
     * 用户注册
     *
     * @param userInformationDTO 用户注册信息
     */
    @Transactional
    public void register(UserInformationDTO userInformationDTO) {
        String code = (String) redisTemplate.opsForValue().get("register:" + userInformationDTO.getEmail());
        if (!Objects.equals(code, userInformationDTO.getVerifyCode())) {
            throw new VerificationCodeErrorException(MessageConstant.VERIFICATION_CODE_ERROR);
        }
        //进行User实体类的封装
        User user = new User();
        BeanUtils.copyProperties(userInformationDTO, user);
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        if (userInformationDTO.getIdentity() == 1) {
            user.setWorkType(1);
            user.setImage("https://pro11.oss-cn-hangzhou.aliyuncs.com/DALL%C2%B7E%202024-09-01%2021.42.24%20-%20A%20cartoon%20illustration%20of%20a%20healthcare%20professional.%20The%20character%20is%20wearing%20a%20white%20lab%20coat%2C%20a%20stethoscope%20around%20their%20neck%2C%20and%20a%20friendly%20smile.webp");
        } else {
            user.setWorkType(2);
            user.setImage("https://pro11.oss-cn-hangzhou.aliyuncs.com/DALL%C2%B7E%202024-09-01%2021.50.49%20-%20A%20cartoon%20illustration%20of%20a%20pharmaceutical%20supplier.%20The%20character%20is%20wearing%20a%20white%20lab%20coat%2C%20glasses%2C%20and%20is%20holding%20a%20box%20labeled%20%27Medicines.%27%20The.webp");
        }
        user.setCreateTime(LocalDateTime.now());
        user.setUpdateTime(LocalDateTime.now());
        log.info("用户信息：{}", user);
        userMapper.register(user);
        //将验证信息放入管理员数据库中
        sendVerificationMessage(userInformationDTO, user);
        //删除缓存数据
        redisTemplate.delete("VerificationInformation:" + userInformationDTO.getIdentity());
    }

    /**
     * 邮箱验证码保存
     *
     * @param email        注册的邮箱
     * @param operationTpe 操作类型，1为注册，2为重置密码
     */
    public void sendCode(String email, Long operationTpe) {
        String code = emailUtil.codeMail(email).toString();
        if (operationTpe.equals(1L)) {
            log.info("邮箱{}注册的验证码为：{}", email, code);
            redisTemplate.opsForValue().set("register:" + email, code, 5, TimeUnit.MINUTES);
        } else {
            log.info("邮箱{}重置密码的验证码为：{}", email, code);
            redisTemplate.opsForValue().set("resetPassword:" + email, code, 5, TimeUnit.MINUTES);
        }
    }

    /**
     * 重置密码
     *
     * @param userInformationDTO 用户信息
     */
    public void resetPassword(UserInformationDTO userInformationDTO) {
        String code = (String) redisTemplate.opsForValue().get(userInformationDTO.getEmail());
        if (!Objects.equals(code, userInformationDTO.getVerifyCode())) {
            throw new VerificationCodeErrorException(MessageConstant.VERIFICATION_CODE_ERROR);
        }
        User user = new User();
        BeanUtils.copyProperties(userInformationDTO, user);
        user.setPassword(passwordEncoder.encode(userInformationDTO.getPassword()));
        log.info("用户更改的信息：{}", user);
        userMapper.resetPassword(user, LocalDateTime.now());
    }

    /**
     * 用户登录
     *
     * @param userLoginDTO 用户登录信息
     * @return 身份信息
     */
    public UserLoginVO login(UserLoginDTO userLoginDTO) {
        //AuthenticationManager进行用户认证
        Authentication authenticate = getAuthentication(userLoginDTO);
        //在Authentication中获取用户信息
        LoginUser loginUser = (LoginUser) authenticate.getPrincipal();
        User u = loginUser.getUser();
        if (u != null && u.getAccountStatus() == 1) {
            UserLoginVO userLoginVO = UserLoginVO.builder()
                    .id(u.getId())
                    .build();
            Map<String, Object> claims = new HashMap<>();
            claims.put(JwtClaimsConstant.ID, userLoginVO.getId());
            String jwt = JwtUtil.createJWT(jwtProperties.getSecretKey(), jwtProperties.getTtl(), claims);
            userLoginVO.setToken(jwt);
            String userId = u.getId().toString();
            //用户信息存入redis
            redisTemplate.opsForValue().set("login:" + userId, loginUser);
            //给用户发送邮件进行提醒
            //先获取用户当前IP
            CloseableHttpClient aDefault = HttpClients.createDefault();
            HttpGet httpGet = new HttpGet("https://restapi.amap.com/v3/ip?key=" + key);
            String location = "北京市";
            try {
                CloseableHttpResponse execute = aDefault.execute(httpGet);
                HttpEntity entity = execute.getEntity();
                String IP = EntityUtils.toString(entity);
                JSONObject jsonObject = JSONObject.parseObject(IP);
                location = jsonObject.getString("province") + jsonObject.getString("city");
                log.info("当前用户登录地址：{}", location);
                execute.close();
                aDefault.close();
            } catch (IOException e) {
                log.error("获取登录位置失败");
            }
            //再发送消息到交换机异步发送邮件进行提醒
            String jsonString = JSON.toJSONString(EmailMessage.builder()
                    .emailType(EmailType.LOGIN.toString())
                    .emailAddress(u.getEmail())
                    .location(location)
                    .build());
            CorrelationData correlationData = new CorrelationData(UUID.randomUUID().toString());
            rabbitTemplate.convertAndSend("email.direct", "emailDirect", jsonString, correlationData);
            return UserLoginVO.builder()
                    .token(jwt)
                    .id(Long.valueOf(userId))
                    .build();
        } else if (u != null && u.getAccountStatus() == 2) {
            throw new AccountStatusException(MessageConstant.ACCOUNT_LOCKED);
        } else if (u != null && u.getAccountStatus() == 3) {
            throw new AccountStatusException(MessageConstant.ACCOUNT_PREPARING);
        } else {
            throw new AccountStatusException(MessageConstant.ACCOUNT_PREPARE_FAILED);
        }
    }

    /**
     * 登出接口
     */
    public void logout() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        LoginUser loginUser = (LoginUser) authentication.getPrincipal();
        Long userId = loginUser.getUser().getId();
        redisTemplate.delete("login:" + userId);
    }

    /**
     * 重新上传身份文件接口
     *
     * @param userInformationDTO 新身份证明文件
     */
    public void ReUploadIdentityFile(UserInformationDTO userInformationDTO) {
        User user = new User();
        if (!userInformationDTO.getUsername().matches("^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+$")) {
            user.setUsername(userInformationDTO.getUsername());
        } else {
            user.setEmail(userInformationDTO.getUsername());
        }
        User u = userMapper.login(user);
        sendVerificationMessage(userInformationDTO, u);
    }

    /**
     * 认证
     *
     * @param userLoginDTO 用户登录信息
     * @return 用户认证结果
     */
    private Authentication getAuthentication(UserLoginDTO userLoginDTO) {
        AuthenticationManager authenticationManager;
        try {
            authenticationManager = authenticationConfiguration.getAuthenticationManager();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(userLoginDTO.getUsernameOrEmail(), userLoginDTO.getPassword());
        Authentication authenticate;
        //如果认证没通过，给出对应提示
        try {
            authenticate = authenticationManager.authenticate(usernamePasswordAuthenticationToken);
        } catch (AuthenticationException e) {
            throw new LoginErrorException(MessageConstant.INFORMATION_ERROR);
        }
        return authenticate;
    }

    /**
     * @param userInformationDTO 用户认证信息
     * @param u                  用户信息
     */
    private void sendVerificationMessage(UserInformationDTO userInformationDTO, User u) {
        List<String> verificationImages = userInformationDTO.getVerificationImages();
        String images = String.join(",", verificationImages);
        IdentityAuthentication identityAuthentication = IdentityAuthentication.builder()
                .applicationTime(LocalDateTime.now())
                .images(images)
                .idNumber(u.getIdNumber())
                .userId(u.getId())
                .workType(u.getWorkType())
                .build();
        userMapper.sendVerificationMessage(identityAuthentication);
    }
}
