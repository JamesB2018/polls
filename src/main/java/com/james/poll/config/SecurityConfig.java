package com.james.poll.config;

import com.james.poll.Security.CustomUserDetailsService;
import com.james.poll.Security.JwtAuthenticationEntryPoint;
import com.james.poll.Security.JwtAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity //Primarily used to enable web security in projects
@EnableGlobalMethodSecurity( //used to enable method level security based on annotations
        securedEnabled = true, //this enables the @Secured annotation which can protect the controller/service methods
        jsr250Enabled = true, //enables the @RolesAllowed annotation that can be used like this
        prePostEnabled = true //enables more complex expression based access control syntax with @PreAuthorize and @PostAuthorize annotations
)
public class SecurityConfig extends WebSecurityConfigurerAdapter { //This class implements Spring Security’s WebSecurityConfigurer interface. It provides default security configurations and allows other classes to extend it and customize the security configurations by overriding its methods.
    @Autowired
    CustomUserDetailsService customUserDetailsService;

    @Autowired
    private JwtAuthenticationEntryPoint unauthorizedHandler; //this class is used to return a 401 unauthorized error to clients that try to access a protected resource without proper authentication

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        return new JwtAuthenticationFilter();
    } //reads JWT authentication token from the Authorization header of all the requests and validates the token then loads user details associated with that token

    @Override
    public void configure(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
        authenticationManagerBuilder
                .userDetailsService(customUserDetailsService)
                .passwordEncoder(passwordEncoder());
    }

    @Bean(BeanIds.AUTHENTICATION_MANAGER)
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception { //The main Spring Security interface for authenticating a user
        return super.authenticationManagerBean(); //I am using the configured AuthenticationManager to authenticate a user in the login API
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .cors()
                    .and()
                .csrf()
                    .disable()
                .exceptionHandling()
                    .authenticationEntryPoint(unauthorizedHandler)
                    .and()
                .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                    .and()
                .authorizeRequests()
                    .antMatchers("/",
                            "/favicon.ico",
                            "/**/*.png",
                            "/**/*.gif",
                            "/**/*.svg",
                            "/**/*.jpg",
                            "/**/*.html",
                            "/**/*.css",
                            "/**/*.js")
                            .permitAll()
                        .antMatchers("/api/auth/**")
                            .permitAll()
                        .antMatchers("/api/user/checkUsernameAvailability", "/api/user/checkEmailAvailability")
                            .permitAll()
                        .antMatchers(HttpMethod.GET, "/api/poll/**", "/api/users/**")
                            .permitAll()
                        .anyRequest()
                            .authenticated();

        //Add the custom JWT security filter
        http.addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
    }
}
