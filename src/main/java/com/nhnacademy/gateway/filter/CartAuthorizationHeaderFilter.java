package com.nhnacademy.gateway.filter;

import com.nhnacademy.gateway.jwt.JwtUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Slf4j
@Component
public class CartAuthorizationHeaderFilter extends AbstractGatewayFilterFactory<CartAuthorizationHeaderFilter.Config> {

    private final JwtUtil jwtUtil;
    private final StringRedisTemplate redisTemplate;

    public CartAuthorizationHeaderFilter(JwtUtil jwtUtil, StringRedisTemplate redisTemplate) {
        super(Config.class);
        this.jwtUtil = jwtUtil;
        this.redisTemplate = redisTemplate;
    }

    public static class Config {
        private String role;

        public String getRole() {
            return role;
        }

        public void setRole(String role) {
            this.role = role;
        }
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();

            // 1. Authorization 헤더 존재 여부 확인
            if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                // [비회원 로직] 헤더가 없으면 검증 없이 그냥 통과 (Guest)
                log.info("Gateway: Authorization 헤더 없음 -> 비회원(Guest)으로 통과");
                return chain.filter(exchange);
            }

            // 2. Authorization 헤더가 있지만 값이 비어있거나 Bearer 형식이 아닌 경우 (선택적: 에러 or 통과)
            // 여기서는 헤더가 "있는데 이상하면" 에러로 처리하는 것이 보안상 안전합니다.
            String authorizationHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
            if (!StringUtils.hasText(authorizationHeader) || !authorizationHeader.startsWith("Bearer ")) {
                return onError(exchange, "Invalid Authorization Header Format", HttpStatus.UNAUTHORIZED);
            }

            // 3. [회원 로직] 토큰 파싱 및 검증
            String token = authorizationHeader.replace("Bearer ", "");

            // 블랙리스트 검사
            if (Boolean.TRUE.equals(redisTemplate.hasKey(token))) {
                return onError(exchange, "이미 로그아웃된 사용자입니다.", HttpStatus.UNAUTHORIZED);
            }

            // 토큰 유효성 검사
            if (!jwtUtil.validateToken(token)) {
                return onError(exchange, "JWT token is not valid", HttpStatus.UNAUTHORIZED);
            }

            // 4. 토큰 정보 추출
            String memberId = String.valueOf(jwtUtil.getMemberId(token));
            String loginId = jwtUtil.getLoginId(token);
            String userRole = jwtUtil.getRole(token);

            // 5. 권한(Role) 체크 (Config에 설정된 경우만)
            if (config.getRole() != null) {
                if (!userRole.equals(config.getRole()) && !userRole.equals("ADMIN")) {
                    return onError(exchange, "권한이 부족합니다.", HttpStatus.FORBIDDEN);
                }
            }

            // 6. 헤더에 회원 정보 추가 후 다운스트림 전달
            ServerHttpRequest modifiedRequest = request.mutate()
                    .header("X-User-ID", memberId)   // 컨트롤러에서 @RequestHeader("X-User-ID")로 받음
                    .header("X-Login-ID", loginId)
                    .header("X-Role", userRole)
                    .build();

            log.info("Gateway: 회원 인증 성공 -> MemberId: {}", memberId);

            return chain.filter(exchange.mutate().request(modifiedRequest).build());
        };
    }

    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
        log.error("Gateway Filter Error: {} status: {}", err, httpStatus); // 에러 로그 추가
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);
        return response.setComplete();
    }
}