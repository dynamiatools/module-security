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


package tools.dynamia.modules.security.services;

import tools.dynamia.modules.security.domain.Profile;
import tools.dynamia.modules.security.domain.User;

import java.util.List;

/**
 * The SeguridadService interface provides various methods for managing security-related operations.
 */
public interface SecurityService {


    User createUser(User usuario);

    void setNewPassword(String username, String currentPassword, String newPassword, String confirmPassword);


    void validatePassword(String password, String rePassword);

    void resetPassword(User usuario, String password, String password2);


    User getCurrentSessionUser();

    void checkAccountDefaultsSettings();

    User loadUserByUsername(String username);


    User getUserByEmail(String email);

    List<Profile> getProfilesByAccountId(Long accountId);

}
