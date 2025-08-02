package com.grow.gateway.filter.init;

import com.grow.gateway.filter.jwt.JwtTokenProvider;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class DataInit {

    private final JwtTokenProvider tokenProvider;

    @PostConstruct
    public void init() {
        log.info("[TEST] JWT 토큰 생성");
        log.info("access_token: {}", tokenProvider.createAccessToken(1L));
        log.info("refresh_token: {}", tokenProvider.createRefreshToken(1L));
    }
}
