package com.example.oauthtest.config;

import com.example.oauthtest.oauth.CustomOAuth2UserService;
import com.example.oauthtest.token.JwtAuthFilter;
import com.example.oauthtest.oauth.OAuth2SuccessHandler;
import com.example.oauthtest.token.TokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@RequiredArgsConstructor
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final CustomOAuth2UserService oAuth2UserService;
    private final OAuth2SuccessHandler successHandler;
    private final TokenService tokenService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.httpBasic().disable()
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)

                .and()

                .authorizeRequests()
                .antMatchers("/token/**").permitAll()
                .antMatchers("/login").permitAll()
                .anyRequest().authenticated()

                .and()

                .oauth2Login()
                .successHandler(successHandler)
                .userInfoEndpoint().userService(oAuth2UserService);

        http.addFilterBefore(new JwtAuthFilter(tokenService), UsernamePasswordAuthenticationFilter.class);

    }
}
