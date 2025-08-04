package com.grow.gateway.filter;

import com.grow.gateway.filter.jwt.JwtProperties;
import com.grow.gateway.filter.jwt.JwtTokenProvider;
import io.jsonwebtoken.ExpiredJwtException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Optional;

import static com.grow.gateway.filter.JwtGatewayFilter.*;

/**
 * JWT 기반 인증 필터 클래스.
 *
 * <p>이 클래스는 Spring Cloud Gateway에서 커스텀 필터를 구현합니다. Reactive 방식으로 동작하며,
 * 쿠키에서 Access Token과 Refresh Token을 추출하여 검증하고, 필요 시 토큰을 재발급합니다.
 * 검증된 사용자 ID(memberId)를 헤더에 추가하여 다운스트림 서비스로 전달합니다.</p>
 *
 * <p>주요 기능:</p>
 * <ul>
 *   <li>쿠키에서 토큰 추출 및 검증</li>
 *   <li>토큰 만료 시 Refresh Token을 이용한 재발급</li>
 *   <li>인증된 사용자 ID를 X-Authorization-Id 헤더에 추가</li>
 *   <li>예외 처리: 만료된 토큰, 유효하지 않은 토큰 등</li>
 * </ul>
 *
 * <p>이 필터는 AbstractGatewayFilterFactory를 상속하여 GatewayFilter를 생성합니다.
 * GatewayFilter는 요청/응답을 수정하거나 인증 로직을 처리하는 데 사용됩니다.
 * Reactive 프로그래밍을 기반으로 하여 비동기 처리를 지원합니다.</p>
 *
 * @see AbstractGatewayFilterFactory
 * @see GatewayFilter
 * @see JwtTokenProvider
 * @see JwtProperties
 */
@Slf4j
@Component
public class JwtGatewayFilter extends AbstractGatewayFilterFactory<Config> {

    private final JwtTokenProvider tokenProvider;
    private final JwtProperties props;

    /**
     * JwtGatewayFilter 생성자.
     *
     * <p>필터 인스턴스를 초기화하며, 필요한 의존성을 주입합니다.</p>
     *
     * @param tokenProvider JWT 토큰 처리 로직을 제공하는 객체
     * @param props JWT 설정 값을 담은 프로퍼티 객체
     */
    public JwtGatewayFilter(JwtTokenProvider tokenProvider,
                            JwtProperties props) {
        super(Config.class);
        this.tokenProvider = tokenProvider;
        this.props = props;
    }

    /**
     * 필터의 핵심 로직을 정의하는 메서드.
     *
     * <p>이 메서드는 GatewayFilter 인스턴스를 반환하며, Reactive 방식으로 요청을 처리합니다.
     * 쿠키에서 토큰을 추출하고 검증한 후, 필요 시 재발급하며 헤더를 수정합니다.
     * Mono를 사용하여 비동기 처리를 지원합니다.</p>
     *
     * <p>처리 순서:</p>
     * <ol>
     *   <li>요청에서 쿠키 추출</li>
     *   <li>Access Token 검증</li>
     *   <li>만료 시 Refresh Token으로 재발급</li>
     *   <li>memberId를 헤더에 추가</li>
     *   <li>다음 필터로 체인 전달</li>
     * </ol>
     *
     * @param config 필터 설정 객체 (현재는 빈 클래스이지만, 필요 시 확장 가능)
     * @return GatewayFilter 인스턴스, Reactive 방식으로 요청/응답 처리
     */
    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            log.info("[Auth Filter] JWT 인증 필터 실행");
            ServerHttpRequest request = exchange.getRequest();
            ServerHttpResponse response = exchange.getResponse();

            // 쿠키에서 access_token 추출
            Optional<String> accessOpt = getCookieValue(request, "access_token");
            if (accessOpt.isEmpty()) {
                return unauthorizedResponse(response, "[TOKEN ERROR] 액세스 토큰이 없습니다.");
            }

            String accessToken = accessOpt.get();
            try {
                if (tokenProvider.validateToken(accessToken)) {
                    Long memberId = tokenProvider.getMemberId(accessToken);
                    log.info("[Auth Filter] 인증 성공, memberId: {}", memberId);

                    // memberId를 헤더에 추가 (다운스트림 서비스로 전달)
                    return chain.filter(addMemberIdInHeader(exchange, request, memberId));
                }
            } catch (ExpiredJwtException expired) {
                // 액세스 만료 시 refresh_token 으로 재발급 시도
                Optional<String> refreshOpt = getCookieValue(request, "refresh_token");

                if (refreshOpt.isPresent() && tokenProvider.validateToken(refreshOpt.get())) {
                    Long memberId = tokenProvider.getMemberId(refreshOpt.get());

                    // 새 토큰 생성
                    String newAccess = tokenProvider.createAccessToken(memberId);
                    String newRefresh = tokenProvider.createRefreshToken(memberId);

                    // 쿠키 재설정 (응답 헤더에 추가)
                    setNewAccessToken(newAccess, newRefresh, response);

                    // memberId를 헤더에 추가
                    return chain.filter(addMemberIdInHeader(exchange, request, memberId));
                }
            } catch (Exception e) {
                return unauthorizedResponse(response, "[TOKEN ERROR] 토큰 검증에 실패했습니다.");
            }
            return unauthorizedResponse(response, "[TOKEN ERROR] 토큰 검증에 실패했습니다.");
        };
    }

    /**
     * 새로운 Access Token과 Refresh Token을 쿠키에 설정하는 메서드.
     *
     * <p>토큰 재발급 시 호출되며, ResponseCookie를 생성하여 응답 헤더에 추가합니다.
     * 보안을 위해 httpOnly와 secure 플래그를 설정하고, sameSite를 Strict으로 지정합니다.</p>
     *
     * @param newAccess 새로운 Access Token 문자열
     * @param newRefresh 새로운 Refresh Token 문자열
     * @param response ServerHttpResponse 객체, 쿠키를 추가할 응답
     */
    private void setNewAccessToken(String newAccess, String newRefresh, ServerHttpResponse response) {
        long accessMaxAge = props.getAccessTokenExpiryDuration().getSeconds();
        long refreshMaxAge = props.getRefreshTokenExpiryDuration().getSeconds();

        ResponseCookie aCookie = ResponseCookie
                .from("access_token", newAccess)
                .httpOnly(true)
                .secure(true)
                .path("/")
                .maxAge(accessMaxAge)
                .sameSite("Strict")
                .build();

        ResponseCookie rCookie = ResponseCookie
                .from("refresh_token", newRefresh)
                .httpOnly(true)
                .secure(true)
                .path("/")
                .maxAge(refreshMaxAge)
                .sameSite("Strict")
                .build();

        response.getHeaders().add(HttpHeaders.SET_COOKIE, aCookie.toString());
        response.getHeaders().add(HttpHeaders.SET_COOKIE, rCookie.toString());
    }

    /**
     * 인증된 memberId를 요청 헤더에 추가하는 메서드.
     *
     * <p>ServerWebExchange를 mutate하여 요청을 수정합니다. X-Authorization-Id 헤더에 memberId를 문자열로 추가합니다.
     * 이는 다운스트림 서비스에서 사용자 식별을 위해 사용됩니다.</p>
     *
     * @param exchange ServerWebExchange 객체, 요청/응답을 포함
     * @param request ServerHttpRequest 객체, 헤더를 수정할 요청
     * @param memberId 추가할 사용자 ID (Long 타입)
     * @return 수정된 ServerWebExchange 객체
     */
    private ServerWebExchange addMemberIdInHeader(ServerWebExchange exchange, ServerHttpRequest request, Long memberId) {
        return exchange.mutate()
                .request(request.mutate()
                        .header("X-Authorization-Id", memberId.toString())
                        .build())
                .build();
    }

    /**
     * 쿠키에서 특정 이름의 값을 추출하는 헬퍼 메서드 (Reactive 방식).
     *
     * <p>요청의 쿠키 목록에서 주어진 이름의 쿠키를 찾아 값을 반환합니다. Optional을 사용하여 값이 없을 수 있음을 처리합니다.</p>
     *
     * @param request ServerHttpRequest 객체, 쿠키를 추출할 요청
     * @param name 추출할 쿠키의 이름 (예: "access_token")
     * @return Optional<String> 형태로 추출된 쿠키 값 (없으면 empty)
     */
    private Optional<String> getCookieValue(ServerHttpRequest request,
                                            String name) {
        return request.getCookies().get(name).stream()
                .filter(cookie -> name.equals(cookie.getName()))
                .map(org.springframework.http.HttpCookie::getValue)
                .findFirst();
    }

    /**
     * 401 Unauthorized 응답을 반환하는 메서드 (Reactive 방식).
     *
     * <p>인증 실패 시 호출되며, JSON 형식의 에러 메시지를 응답 바디에 작성합니다.
     * Mono를 사용하여 비동기적으로 응답을 처리합니다.</p>
     *
     * @param response ServerHttpResponse 객체, 상태 코드와 바디를 설정할 응답
     * @param message 응답에 포함할 에러 메시지
     * @return Mono<Void> 형태로 응답 쓰기 완료를 나타냄
     */
    private Mono<Void> unauthorizedResponse(ServerHttpResponse response,
                                            String message) {
        response.setStatusCode(org.springframework.http.HttpStatus.UNAUTHORIZED);
        response.getHeaders().add(HttpHeaders.CONTENT_TYPE, "application/json");
        byte[] bytes = ("{\"error\": \"" + message + "\"}").getBytes();
        return response.writeWith(Mono.just(response.bufferFactory().wrap(bytes)));
    }

    /**
     * 필터 설정을 위한 내부 정적 클래스.
     *
     * <p>현재는 빈 클래스이지만, 필터의 동작을 커스터마이징하기 위한 설정 값을 추가할 수 있습니다.
     * 예: 특정 경로 무시, 토큰 타입 변경 등.</p>
     */
    public static class Config {
    }
}
