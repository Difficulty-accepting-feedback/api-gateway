package com.grow.gateway.filter.mdc;

import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.util.context.Context;

import java.util.Map;
import java.util.UUID;

@Slf4j
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class WebMDCFilter implements WebFilter{

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        ServerHttpResponse response = exchange.getResponse();

        // MDC 값 생성
        String traceId = UUID.randomUUID().toString();
        String clientIp = getClientIp(request);
        String requestUri = request.getURI().getPath();

        // 요청 헤더에 값을 추가 (마이크로서비스 전달용)
        ServerHttpRequest modifiedRequest = request
                .mutate()
                .header("X-Trace-Id", traceId)
                .header("X-Client-Ip", clientIp)
                .header("X-Request-Uri", requestUri)
                .build();

        exchange = exchange.mutate().request(modifiedRequest).build();

        // MDC 설정 및 Context 전파
        Map<String, String> mdcMap = Map.of(
                "traceId", traceId,
                "clientIp", clientIp,
                "requestUri", requestUri
        );
        MDC.setContextMap(mdcMap);

        log.debug("requestUri: {}", requestUri);
        log.debug("Client IP: {}", clientIp);
        log.debug("Trace ID: {}", traceId);

        // 체인 실행 및 Context 쓰기
        return chain.filter(exchange)
                .contextWrite(ctx -> Context.of("mdcMap", mdcMap).putAll(ctx))  // MDC 맵을 Context에 저장
                .doOnSuccess(v -> log.info("Gateway response completed"))
                .doOnError(throwable -> log.error("Gateway error: ", throwable))
                .doFinally(signal -> {
                    MDC.clear();  // MDC 정리
                });
    }

    private String getClientIp(ServerHttpRequest request) {
        String xfHeader = request.getHeaders().getFirst("X-Forwarded-For");
        if (xfHeader != null && !xfHeader.isEmpty()) {
            return xfHeader.split(",")[0].trim();
        }
        return request.getRemoteAddress().toString();
    }
}
