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
import org.springframework.util.StringUtils; // 추가됨
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Slf4j
@Component
public class AuthorizationHeaderGatewayFilterFactory extends AbstractGatewayFilterFactory<AuthorizationHeaderGatewayFilterFactory.Config> {

    private final JwtUtil jwtUtil;
    private final StringRedisTemplate redisTemplate;

    public AuthorizationHeaderGatewayFilterFactory(JwtUtil jwtUtil, StringRedisTemplate redisTemplate) {
        super(Config.class);
        this.jwtUtil = jwtUtil;
        this.redisTemplate = redisTemplate;
    }

    public static class Config {
        private String role;
        private boolean required = true; // [중요] 기본값 true (인증 필수)

        public String getRole() {
            return role;
        }

        public void setRole(String role) {
            this.role = role;
        }

        public boolean isRequired() { // [중요] getter 추가
            return required;
        }

        public void setRequired(boolean required) { // [중요] setter 추가
            this.required = required;
        }
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();

            // 1. 헤더가 없는 경우 처리
            if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                if (config.isRequired()) {
                    // 필수(true)인데 없으면 -> 에러
                    return onError(exchange, "No authorization header", HttpStatus.UNAUTHORIZED);
                } else {
                    // 필수 아니면(false) -> 그냥 통과 (비회원)
                    return chain.filter(exchange);
                }
            }

            // 2. 헤더 값 가져오기
            String authorizationHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
            if (!StringUtils.hasText(authorizationHeader) || !authorizationHeader.startsWith("Bearer ")) {
                // 헤더 형식이 이상하면 -> 에러 (required=false여도, 이상한 헤더를 보냈으면 막는게 안전)
                return onError(exchange, "Invalid Authorization Header", HttpStatus.UNAUTHORIZED);
            }

            String token = authorizationHeader.replace("Bearer ", "");

            // 3. 토큰 검증
            if (Boolean.TRUE.equals(redisTemplate.hasKey(token))) {
                return onError(exchange, "이미 로그아웃된 사용자입니다.", HttpStatus.UNAUTHORIZED);
            }

            if (!jwtUtil.validateToken(token)) {
                return onError(exchange, "JWT token is not valid", HttpStatus.UNAUTHORIZED);
            }

            // 4. 검증 성공 시 정보 추출
            String memberId = String.valueOf(jwtUtil.getMemberId(token));

            String userRole = jwtUtil.getRole(token);

            if (config.getRole() != null) {
                if (!userRole.equals(config.getRole()) && !userRole.equals("ADMIN")) {
                    return onError(exchange, "권한이 부족합니다.", HttpStatus.FORBIDDEN);
                }
            }

            ServerHttpRequest modifiedRequest = request.mutate()
                    .header("X-User-ID", memberId)
                    .header("X-Role", userRole)
                    .build();

            return chain.filter(exchange.mutate().request(modifiedRequest).build());
        };
    }

    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
        log.error("Gateway Filter Error: {} status: {}", err, httpStatus); // 로그 추가
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);
        return response.setComplete();
    }
}