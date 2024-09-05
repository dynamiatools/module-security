
/*
 * Copyright (c) 2009 - 2021 Dynamia Soluciones IT SAS  All Rights Reserved
 *
 * Todos los Derechos Reservados  2009 - 2021
 *
 * Este archivo es propiedad de Dynamia Soluciones IT NIT 900302344-1 en Colombia / Sur America,
 * esta estrictamente prohibida su copia o distribución sin previa autorización del propietario.
 * Puede contactarnos a info@dynamiasoluciones.com o visitar nuestro sitio web
 * https://www.dynamiasoluciones.com
 *
 * Autor: Ing. Mario Serrano Leones <mario@dynamiasoluciones.com>
 */

package tools.dynamia.modules.security;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.RequestCacheConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.firewall.HttpFirewall;
import org.springframework.security.web.firewall.StrictHttpFirewall;
import tools.dynamia.commons.logger.LoggingService;
import tools.dynamia.commons.logger.SLF4JLoggingService;
import tools.dynamia.domain.DefaultEntityReferenceRepository;
import tools.dynamia.domain.EntityReferenceRepository;
import tools.dynamia.modules.security.domain.Profile;
import tools.dynamia.modules.security.domain.User;

import java.util.List;
import java.util.stream.Stream;

/**
 * @author Mario Serrano Leones
 */

@Configuration
@Order(Integer.MIN_VALUE)
@EnableWebSecurity
@EnableMethodSecurity(securedEnabled = true, jsr250Enabled = true)
public class DynamiaSecurityConfiguration {


    private final UserDetailsService userDetailService;
    private final List<IgnoringSecurityMatcher> ignorings;

    private final List<SecurityConfigurationInterceptor> configInterceptors;

    private LoggingService logger = new SLF4JLoggingService(DynamiaSecurityConfiguration.class);


    public DynamiaSecurityConfiguration(UserDetailsService userDetailService, List<IgnoringSecurityMatcher> ignorings,
                                        List<SecurityConfigurationInterceptor> configInterceptors) {
        this.userDetailService = userDetailService;
        this.ignorings = ignorings;
        this.configInterceptors = configInterceptors;
        logger.info("Starting Dynamia Tools Security configuration");
    }


    @Bean
    @Primary
    public AuthenticationManager authenticationManager(HttpSecurity http,
                                                       PasswordEncoder passwordEncoder) throws Exception {
        var auth = http.getSharedObject(AuthenticationManagerBuilder.class);
        auth.userDetailsService(userDetailService)
                .passwordEncoder(passwordEncoder);


        if (configInterceptors != null) {
            for (SecurityConfigurationInterceptor interceptor : configInterceptors) {
                interceptor.configure(auth);
            }
        }

        return auth.build();
    }

    @Bean
    @Primary
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   AuthenticationManager authMgr,
                                                   SavedRequestAwareAuthenticationSuccessHandler successHandler) throws Exception {
        String[] publicRoutes = ignorings.stream().flatMap(ism -> Stream.of(ism.matchers())).toArray(String[]::new);

        http
                .userDetailsService(userDetailService)
                .authorizeHttpRequests(c -> c
                        .requestMatchers("/login", "/login/recovery").permitAll()
                        .requestMatchers(publicRoutes).permitAll()
                        .anyRequest().authenticated())
                .formLogin(c -> c
                        .usernameParameter("username")
                        .passwordParameter("password")
                        .defaultSuccessUrl("/", false)
                        .loginPage("/login")
                        .permitAll())
                .logout(c -> c
                        .logoutUrl("/logout")
                        .permitAll())
                .httpBasic(AbstractHttpConfigurer::disable)
                .csrf(AbstractHttpConfigurer::disable)
                .anonymous(AbstractHttpConfigurer::disable)
                .requestCache(RequestCacheConfigurer::disable)
                .addFilter(new UserTokenAuthenticationFilter(authMgr));


        http.securityContext(c -> c.
                securityContextRepository(new HttpSessionSecurityContextRepository())
        );

        if (configInterceptors != null) {
            for (SecurityConfigurationInterceptor interceptor : configInterceptors) {
                interceptor.configure(http);
            }
        }

        return http.build();
    }

    @Bean
    @Primary
    public WebSecurityCustomizer webSecurityCustomizer(HttpFirewall httpFirewall) {
        return (web) -> {


            if (configInterceptors != null) {
                for (SecurityConfigurationInterceptor interceptor : configInterceptors) {
                    interceptor.configure(web);
                }
            }

            web.httpFirewall(httpFirewall);
        };
    }

    @Bean
    @Primary
    public HttpFirewall firewall() {
        StrictHttpFirewall firewall = new StrictHttpFirewall();
        firewall.setAllowBackSlash(true);
        firewall.setAllowSemicolon(true);

        return firewall;
    }

    @Bean
    @ConditionalOnMissingBean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(5);
    }


    @Bean
    public SavedRequestAwareAuthenticationSuccessHandler savedRequestAwareAuthenticationSuccessHandler() {
        SavedRequestAwareAuthenticationSuccessHandler auth = new SavedRequestAwareAuthenticationSuccessHandler();
        auth.setTargetUrlParameter("targetUrl");
        return auth;
    }


    @Bean
    public EntityReferenceRepository<Long> usersEntityReferenceRepository() {
        DefaultEntityReferenceRepository<Long> repo = new DefaultEntityReferenceRepository<>(User.class, "username");
        repo.setCacheable(true);

        return repo;
    }

    @Bean
    public EntityReferenceRepository<Long> userProfilesEntityReferenceRepository() {
        DefaultEntityReferenceRepository<Long> repo = new DefaultEntityReferenceRepository<>(Profile.class, "name");
        repo.setCacheable(true);

        return repo;
    }


}
