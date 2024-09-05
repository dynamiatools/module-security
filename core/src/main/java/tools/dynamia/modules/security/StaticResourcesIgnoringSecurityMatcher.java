
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

import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Component;

import java.util.stream.Stream;

/**
 * @author Mario Serrano Leones
 */
@Component
public class StaticResourcesIgnoringSecurityMatcher implements SecurityConfigurationInterceptor {


    public String[] matchers() {
        return new String[]{
                "/login", "/login/recovery", "/styles/**", "/css/**", "/images/**", "/fonts/**", "/img/**", "/js/**", "/assets/**", "/static/**",
                "/storage/**", "/*.ico", "/favicon.ico", "/ws-commands/**", "/ws-commands", "/*.png", "/*.svg", "/root/**", "/zkcomet/**", "/zkwm/**",
                "/*.manifest", "/*.webmanifest", "/static/*.png", "/static/*.ico", "/web/**", "/zkau/**", "/zkau", "/error", "/errors"
        };
    }

    @Override
    public void configure(WebSecurity web) {
        RequestMatcher[] ignoreMatches = Stream.of(matchers())
                .map(AntPathRequestMatcher::antMatcher).toArray(RequestMatcher[]::new);
        web.ignoring().requestMatchers(ignoreMatches);
    }

}
