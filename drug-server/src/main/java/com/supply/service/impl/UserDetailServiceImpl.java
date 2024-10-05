package com.supply.service.impl;

import com.supply.constant.MessageConstant;
import com.supply.entity.User;
import com.supply.entity.LoginUser;
import com.supply.exception.LoginErrorException;
import com.supply.mapper.UserMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class UserDetailServiceImpl implements UserDetailsService {

    private final UserMapper userMapper;

    private final RedisTemplate<Object,Object> redisTemplate;

    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        if(!Objects.isNull(redisTemplate.opsForValue().get("user doesn't existence:" + username))){
            throw new LoginErrorException(MessageConstant.INFORMATION_ERROR);
        }
        User user;
        if (!username.matches("^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+$")) {
            user = User.builder()
                    .username(username)
                    .build();
        } else {
            user = User.builder()
                    .email(username)
                    .build();
        }
        User u = userMapper.login(user);
        if (Objects.isNull(u)) {
            //防止缓存穿透，缓存空数据并设置过期时间
            redisTemplate.opsForValue().set("user doesn't existence:" + username,"1",30, TimeUnit.MINUTES);
            throw new LoginErrorException(MessageConstant.INFORMATION_ERROR);
        }
        //查询对应的权限信息
        List<String> list = userMapper.getAuthority(u.getId());
        //把数据封装为UserDetails对象返回
        return new LoginUser(u,list);
    }
}