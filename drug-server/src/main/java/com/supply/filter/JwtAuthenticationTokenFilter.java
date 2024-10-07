package com.supply.filter;

import com.alibaba.fastjson.JSON;
import com.supply.context.WebSocketContext;
import com.supply.entity.LoginUser;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.HttpStatus;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import com.supply.properties.JwtProperties;
import com.supply.utils.JwtUtil;

import java.io.IOException;
import java.util.Objects;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationTokenFilter extends OncePerRequestFilter {

    private final RedisTemplate<Object, Object> redisTemplate;

    private final JwtProperties jwtProperties;

    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // 获取 token
        String token = request.getHeader("token");

        // 如果没有token，直接放行
        if (!StringUtils.hasText(token)) {
            filterChain.doFilter(request, response);
            return;
        }

        // 解析 token
        String userId;
        try {
            Claims claims = JwtUtil.parseJWT(jwtProperties.getSecretKey(), token);
            userId = claims.get("id").toString();
        } catch (Exception e) {
            log.error("Token解析失败: {}", e.getMessage());
            response.setStatus(HttpStatus.SC_UNAUTHORIZED);
            response.getWriter().write("无效或过期的令牌");
            return;
        }

        // 从 Redis 中获取用户信息
        String jsonData = Objects.requireNonNull(redisTemplate.opsForValue().get("login:" + userId)).toString();
        LoginUser loginUser = JSON.parseObject(jsonData, LoginUser.class);

        if (Objects.isNull(loginUser)) {
            log.warn("用户未登录或会话已过期, userId: {}", userId);
            response.setStatus(HttpStatus.SC_UNAUTHORIZED); // 返回401未授权
            response.getWriter().write("用户未登录或会话已过期");
            return;
        }

        // 存入 SecurityContextHolder
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                loginUser, null, loginUser.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);

        // 日志记录
        log.info("用户 {} 验证通过", userId);

        //如果是websocket连接请求，保存当前用户信息
        if(request.getRequestURI().equals("/chat")){
            WebSocketContext.setCurrentId(Long.valueOf(userId));
        }

        // 继续执行过滤器链
        filterChain.doFilter(request, response);
    }
}
