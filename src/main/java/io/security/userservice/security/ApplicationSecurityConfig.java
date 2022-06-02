/*

Spring Security without the WebSecurityConfigurerAdapter
https://spring.io/blog/2022/02/21/spring-security-without-the-websecurityconfigureradapter
more info
https://spring.io/guides/topicals/spring-security-architecture#:~:text=The%20filter%20chain%20provides%20the,at%20a%20more%20granular%20level.

 */


package io.security.userservice.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;


import static io.security.userservice.security.ApplicationUserPermission.*;
import static io.security.userservice.security.ApplicationUserRole.*;
import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig {

    private final PasswordEncoder passwordEncoder ;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }


    @Bean
    @Order(0)
    SecurityFilterChain resources(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .authorizeRequests()
                    .antMatchers("/index", "/css/*","/js/*").permitAll()
                    .antMatchers("/api/**").hasRole(STUDENT.name())
                    /*.antMatchers(HttpMethod.DELETE,"/managment/api/**").hasAuthority(COURSE_WRITE.getPermission())
                    .antMatchers(HttpMethod.POST,"/managment/api/**").hasAuthority(COURSE_WRITE.getPermission())
                    .antMatchers(HttpMethod.PUT,"/managment/api/**").hasAuthority(COURSE_WRITE.getPermission())
                    .antMatchers("/managment/api/**").hasAnyRole(ADMIN.name(), ADMINTRAINEE.name())*/
                .anyRequest()
                  .authenticated()
                  .and().httpBasic() /*.and().csrf().disable()*/ ;



        return http.build();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests((authz) -> authz.anyRequest().authenticated())
                .httpBasic(withDefaults()) ;



        return http.build();
    }

    @Bean
    protected UserDetailsService userDetailsService(){
        UserDetails annaSmithUser = User.builder()
                .username("annasmith")
                .password(passwordEncoder.encode("password"))
               // .roles(STUDENT.name()) //ROLE_USER
                .authorities(STUDENT.getGrantedAuthorities())
                .build();

        UserDetails lindaUser = User.builder()
                .username("linda")
                .password(passwordEncoder.encode("password123"))
                //.roles(ADMIN.name()) //ROLE_ADMIN
                .authorities(ADMIN.getGrantedAuthorities())
                .build();

        UserDetails tomUser = User.builder()
                .username("tom")
                .password(passwordEncoder.encode("password123"))
                //.roles(ADMINTRAINEE.name()) //ROLE_ADMINTRAINEE
                .authorities(ADMINTRAINEE.getGrantedAuthorities()) //ROLE_ADMINTRAINEE
                .build();

        return new InMemoryUserDetailsManager(annaSmithUser, lindaUser, tomUser) ;
    }



}

/*
for demos
//https://stackoverflow.com/questions/49847791/java-spring-security-user-withdefaultpasswordencoder-is-deprecated
    @Bean
    public UserDetailsService userDetailsService() {

        User.UserBuilder users = User.withDefaultPasswordEncoder();
        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
        manager.createUser(users.username("annasmith").password("password").roles("STUDENT").build());
        manager.createUser(users.username("admin").password("password").roles("USER", "ADMIN").build());
        return manager;

    }
 */





