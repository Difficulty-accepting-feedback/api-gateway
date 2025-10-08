package com.grow.gateway.filter.mdc;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.annotation.Order;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.UUID;

import static org.springframework.core.Ordered.HIGHEST_PRECEDENCE;

@Slf4j
@Component
@Order(HIGHEST_PRECEDENCE)
public class WebMDCFilterFactory extends AbstractGatewayFilterFactory<WebMDCFilterFactory.Config> {

    public WebMDCFilterFactory() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            ServerHttpResponse response = exchange.getResponse();

            // MDC 값 생성 (기존 로직)
            String traceId = UUID.randomUUID().toString();
            String clientIp = getClientIp(request);
            String requestUri = request.getURI().getPath();

            // 헤더 수정
            ServerHttpRequest modifiedRequest = request
                    .mutate()
                    .header("X-Trace-Id", traceId)
                    .header("X-Client-Ip", clientIp)
                    .header("X-Request-Uri", requestUri)
                    .build();

            exchange = exchange.mutate().request(modifiedRequest).build();

            // MDC 및 Context 설정
            Map<String, String> mdcMap = Map.of(
                    "traceId", traceId,
                    "clientIp", clientIp,
                    "requestUri", requestUri);
            MDC.setContextMap(mdcMap);

            log.info("requestUri: {}", requestUri);
            log.info("Client IP: {}", clientIp);
            log.info("Trace ID: {}", traceId);

            return chain.filter(exchange)
                    .doOnSuccess(v -> log.info("Gateway response completed"))
                    .doOnError(throwable -> log.error("Gateway error: ", throwable))
                    .doFinally(signal -> MDC.clear());
        };
    }

    private String getClientIp(ServerHttpRequest request) {
        String xfHeader = request.getHeaders().getFirst("X-Forwarded-For");
        if (xfHeader != null && !xfHeader.isEmpty()) {
            return xfHeader.split(",")[0].trim();
        }
        return request.getRemoteAddress().toString();
    }

    @Data
    public static class Config {
        // yml에서 설정할 args
    }
}
