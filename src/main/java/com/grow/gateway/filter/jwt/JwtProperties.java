package com.grow.gateway.filter.jwt;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.time.Duration;

@Getter
@Setter
@Component
@ConfigurationProperties(prefix = "jwt")
public class JwtProperties {
	private String secret;
	private long accessTokenExpiration;
	private long refreshTokenExpiration;

	public Duration getAccessTokenExpiryDuration() {
		return Duration.ofSeconds(accessTokenExpiration);
	}

	public Duration getRefreshTokenExpiryDuration() {
		return Duration.ofSeconds(refreshTokenExpiration);
	}
}