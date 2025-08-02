package com.grow.gateway.filter.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.Instant;
import java.util.Date;

/**
 * JWT 토큰을 생성하고 검증하는 컴포넌트
 */
@Component
@RequiredArgsConstructor
public class JwtTokenProvider {

	private final JwtProperties props;
	private Key key;

	@PostConstruct
	public void init() {
		this.key = Keys.hmacShaKeyFor(
			props.getSecret().getBytes(StandardCharsets.UTF_8)
		);
	}

	public String createAccessToken(Long memberId) {
		Instant now = Instant.now();
		Date exp = Date.from(
			Instant.now().plus(props.getAccessTokenExpiryDuration())
		);
		return Jwts.builder()
			.setSubject(memberId.toString())
			.setIssuedAt(Date.from(now))
			.setExpiration(exp)
			.signWith(key, SignatureAlgorithm.HS256)
			.compact();
	}

	public String createRefreshToken(Long memberId) {
		Instant now = Instant.now();
		Date exp = Date.from(
			Instant.now().plus(props.getRefreshTokenExpiryDuration())
		);
		return Jwts.builder()
			.setSubject(memberId.toString())
			.setIssuedAt(Date.from(now))
			.setExpiration(exp)
			.signWith(key, SignatureAlgorithm.HS256)
			.compact();
	}

	public boolean validateToken(String token) {
		try {
			Jwts.parserBuilder()
				.setSigningKey(key)
				.build()
				.parseClaimsJws(token);
			return true;
		} catch (Exception e) {
			return false;
		}
	}

	public Long getMemberId(String token) {
		Claims claims = Jwts.parserBuilder()
			.setSigningKey(key)
			.build()
			.parseClaimsJws(token)
			.getBody();
		return Long.valueOf(claims.getSubject());
	}
}