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
        private boolean required = true;

        public String getRole() { return role; }
        public void setRole(String role) { this.role = role; }

        public boolean isRequired() { return required; }
        public void setRequired(boolean required) { this.required = required; }
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();

            if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                if (config.isRequired()) {
                    return onError(exchange, "No authorization header", HttpStatus.UNAUTHORIZED);
                } else {
                    return chain.filter(exchange);
                }
            }

            String authorizationHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
            if (!StringUtils.hasText(authorizationHeader) || !authorizationHeader.startsWith("Bearer ")) {
                return onError(exchange, "Invalid Authorization Header Format", HttpStatus.UNAUTHORIZED);
            }

            String token = authorizationHeader.replace("Bearer ", "");

            if (Boolean.TRUE.equals(redisTemplate.hasKey(token))) {
                return onError(exchange, "이미 로그아웃된 사용자입니다.", HttpStatus.UNAUTHORIZED);
            }

            if (!jwtUtil.validateToken(token)) {
                return onError(exchange, "JWT token is not valid", HttpStatus.UNAUTHORIZED);
            }

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
        log.error("Gateway Filter Error: {} status: {}", err, httpStatus);
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);
        return response.setComplete();
    }
}