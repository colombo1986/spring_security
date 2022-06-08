/*

Spring Security without the WebSecurityConfigurerAdapter
https://spring.io/blog/2022/02/21/spring-security-without-the-websecurityconfigureradapter
more info
https://spring.io/guides/topicals/spring-security-architecture#:~:text=The%20filter%20chain%20provides%20the,at%20a%20more%20granular%20level.

 */


package io.security.userservice.security;

import io.security.userservice.auth.ApplicationUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;


import java.util.concurrent.TimeUnit;

import static io.security.userservice.security.ApplicationUserRole.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig {

    private final PasswordEncoder passwordEncoder ;
    private final ApplicationUserService applicationUserService;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder, ApplicationUserService applicationUserService) {
        this.passwordEncoder = passwordEncoder;
        this.applicationUserService = applicationUserService;
    }


    @Bean
    @Order(0)
    SecurityFilterChain resources(HttpSecurity http) throws Exception {

        http
                .csrf().disable()
                .authorizeRequests()
                .antMatchers("/login","/index", "/css/*","/js/*").permitAll()
                .antMatchers("/api/**").hasRole(STUDENT.name())
                .anyRequest()
                .authenticated()
                    .and()
                    .formLogin()
                    .loginPage("/login")
                    .loginProcessingUrl("/login")
                    .defaultSuccessUrl("/courses",true)
                        .and()
                         .rememberMe().tokenValiditySeconds((int)TimeUnit.DAYS.toSeconds(21))
                         .key("uniqueAndSecret")
                         .userDetailsService(applicationUserService)
                          .and()
                                .logout()
                                .logoutUrl("/logout")
                                .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
                                .clearAuthentication(true)
                                .invalidateHttpSession(true)
                                .deleteCookies("JSESSIONID", "remember-me")
                                .logoutSuccessUrl("/login");



        return http.build();
    }

}






