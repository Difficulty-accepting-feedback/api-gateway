package com.grow.gateway.filter.mdc;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.MDC;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;


import java.io.IOException;
import java.util.UUID;

@Order(Ordered.HIGHEST_PRECEDENCE) // 제일 먼저 실행될 필터
@Component
public class MDCFilter implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        String traceId = UUID.randomUUID().toString();

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        String clientIp = getClientIp(httpRequest); // 클라이언트 IP 가져오기 (X-Forwarded-For 헤더도 체크)

        String requestUri = httpRequest.getRequestURI();

        HttpServletResponse httpResponse = (HttpServletResponse) response;
        httpResponse.addHeader("X-Trace-Id", traceId); // X-Trace-Id 헤더에 추가
        httpResponse.addHeader("X-Client-Ip", clientIp); // X-Client-Ip 헤더에 추가
        httpResponse.addHeader("X-Request-Uri", requestUri); // X-Request-Uri 헤더에 추가
        try {
            chain.doFilter(request, response);
        } finally {
            MDC.remove("traceId");
            MDC.remove("clientIp");
            MDC.remove("requestUri");
        }
    }

    private String getClientIp(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader != null) {
            return xfHeader.split(",")[0]; // 프록시 환경 고려
        }
        return request.getRemoteAddr();
    }
}