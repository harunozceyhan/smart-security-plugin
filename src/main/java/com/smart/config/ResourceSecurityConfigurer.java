package com.smart.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Configuration
@EnableWebSecurity
@Profile(value = {"dev", "prod"})
public class ResourceSecurityConfigurer extends WebSecurityConfigurerAdapter {

    @Value("${security.signing.key}")
    private String signingKey;

	@Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.csrf().disable().authorizeRequests().antMatchers("/actuator/health").permitAll().and().
        addFilterBefore(new JwtTokenAuthenticationFilter(signingKey), BasicAuthenticationFilter.class).authorizeRequests().anyRequest().authenticated().and().
        sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and().httpBasic().disable().authorizeRequests().and().formLogin().disable();
	}
}