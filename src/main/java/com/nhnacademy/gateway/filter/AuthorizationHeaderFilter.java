package com.nhnacademy.gateway.filter;

import com.nhnacademy.gateway.jwt.JwtUtil; // 패키지명 확인!
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
@Slf4j
@Component
public class AuthorizationHeaderFilter extends AbstractGatewayFilterFactory<AuthorizationHeaderFilter.Config> {

    private final JwtUtil jwtUtil;
    private final StringRedisTemplate redisTemplate;

    public AuthorizationHeaderFilter(JwtUtil jwtUtil, StringRedisTemplate redisTemplate) {
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
            if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                return onError(exchange, "No authorization header", HttpStatus.UNAUTHORIZED);
            }

            String authorizationHeader = request.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
            String token = authorizationHeader.replace("Bearer ", "");

            boolean isBlacklisted = Boolean.TRUE.equals(redisTemplate.hasKey(token));
            log.info("Gateway 블랙리스트 검사 결과: {}", isBlacklisted); // ★ 로그 확인!

            if (!jwtUtil.validateToken(token)) {
                return onError(exchange, "JWT token is not valid", HttpStatus.UNAUTHORIZED);
            }

            if (Boolean.TRUE.equals(redisTemplate.hasKey(token))) {
                return onError(exchange, "이미 로그아웃된 사용자입니다.", HttpStatus.UNAUTHORIZED);
            }

            String memberId = String.valueOf(jwtUtil.getMemberId(token));
            String loginId = jwtUtil.getLoginId(token);
            String userRole = jwtUtil.getRole(token);

            if (config.getRole() != null) {
                if (!userRole.equals(config.getRole()) && !userRole.equals("ADMIN")) {
                    return onError(exchange, "권한이 부족합니다.", HttpStatus.FORBIDDEN);
                }
            }

            ServerHttpRequest modifiedRequest = request.mutate()
                    .header("X-User-ID", memberId)
                    .header("X-Login-ID", loginId)
                    .header("X-Role", userRole)
                    .build();

            return chain.filter(exchange.mutate().request(modifiedRequest).build());
        };
    }

    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);
        return response.setComplete();
    }
}