package com.smart.config;

import java.io.IOException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

import org.apache.commons.codec.binary.Base64;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import java.security.KeyFactory;

public class JwtTokenAuthenticationFilter extends  OncePerRequestFilter {
    
	private String signingKey;
	
	public JwtTokenAuthenticationFilter(String signingKey) {
		this.signingKey = signingKey;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
		try {	// exceptions might be thrown in creating the claims if for example the token is expired
			UsernamePasswordAuthenticationToken authentication = getAuthentication(request);
			SecurityContextHolder.getContext().setAuthentication(authentication);
		} catch (Exception e) {
			SecurityContextHolder.clearContext();
		}
		chain.doFilter(request, response);
	}

	private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) {
        String token = request.getHeader("Authorization");
        if (token != null) {
			try {	
				KeyFactory kf = KeyFactory.getInstance("RSA");
				X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.decodeBase64(signingKey));
				RSAPublicKey pubKey = (RSAPublicKey) kf.generatePublic(keySpecX509);
				DecodedJWT decodedJWT = JWT.require(Algorithm.RSA256(pubKey, null)).build().verify(token.replace("Bearer ", ""));
				String user = decodedJWT.getClaim("preferred_username").asString();
				// ((ArrayList)decodedJWT.getClaim("realm_access").asMap().get("roles")).get(0)
				if (user != null) {
					return new UsernamePasswordAuthenticationToken(user, null, new ArrayList<>());
				}
				return null;
			} catch (Exception e) {
				SecurityContextHolder.clearContext();
			}
		}
		SecurityContextHolder.clearContext();
        return null;
    }

}