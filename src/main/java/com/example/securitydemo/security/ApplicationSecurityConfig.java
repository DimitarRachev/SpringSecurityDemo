package com.example.securitydemo.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.concurrent.TimeUnit;

import static com.example.securitydemo.security.ApplicationUserPermission.*;
import static com.example.securitydemo.security.ApplicationUserRole.ADMIN;
import static com.example.securitydemo.security.ApplicationUserRole.ADMIN_TRAINEE;
import static com.example.securitydemo.security.ApplicationUserRole.STUDENT;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;

    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
//                .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())   //csfr is recommended when browser can access end points, if only using
//                .and()                                                                       //applications it's recommended to be csrf().disabled()
                .csrf().disable()
                .authorizeRequests()
                        .antMatchers("/", "index", "/css/*", "/js/*")
                        .permitAll()
                .antMatchers("/api/**")
                .hasRole(STUDENT.name())
        //                .antMatchers(HttpMethod.DELETE, "/managment/api/**").hasAnyAuthority(COURSE_WRITE.getPermission())     //replaced with @PreAutorise anotation
        //                .antMatchers(HttpMethod.POST, "/managment/api/**").hasAnyAuthority(COURSE_WRITE.getPermission())       //replaced with @PreAutorise anotation
        //                .antMatchers(HttpMethod.PUT, "/managment/api/**").hasAnyAuthority(COURSE_WRITE.getPermission())        //replaced with @PreAutorise anotation
        //                .antMatchers(HttpMethod.GET, "/management/api/**").hasAnyRole(ADMIN.name(), ADMIN_TRAINEE.name())      //replaced with @PreAutorise anotation
                .anyRequest()
                .authenticated()
                .and()
                .formLogin()
                        .loginPage("/login").permitAll()
                        .defaultSuccessUrl("/courses", true)
                        .passwordParameter("password")  //same as 'name="username" ' in login form
                        .usernameParameter("username")  //same as 'name="username" ' in login form
                .and()
                        .rememberMe().tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21)).key("somethingVerySecure")     //default to 2 weeks, changed to 21 days
                        .rememberMeParameter("remember-me")//same as 'name="remember-me"' in login form
                .and()
                .logout()
                        .logoutUrl("/logout")
                        .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET")) //need to be POST for csrf to work properly, also is a good practice
                        .clearAuthentication(true)
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID", "remember-me")
                        .logoutSuccessUrl("/login");
    }

    @Override
    @Bean
    protected UserDetailsService userDetailsService() {
        UserDetails annaSmithUser = User.builder()
                .username("annasmith")
                .password(passwordEncoder.encode("password"))
//                .roles(STUDENT.name()) //ROLE_STUDENT
                .authorities(STUDENT.getGrantedAuthorities())
                .build();

        UserDetails admin = User.builder()
                .username("admin")
                .password(passwordEncoder.encode("admin"))
//                .roles(ADMIN.name()) //ROLE_ADMIN
                .authorities(ADMIN.getGrantedAuthorities())
                .build();

        UserDetails tomUser = User.builder()
                .username("tom")
                .password(passwordEncoder.encode("tom"))
//                .roles(ADMIN_TRAINEE.name()) //ROLE_ADMIN_TRAINEE
                .authorities(ADMIN_TRAINEE.getGrantedAuthorities())
                .build();

        return new InMemoryUserDetailsManager(annaSmithUser, admin, tomUser);
    }
}
