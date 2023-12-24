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


package tools.dynamia.modules.security.services.impl;

import jakarta.annotation.PostConstruct;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import tools.dynamia.domain.ValidationError;
import tools.dynamia.domain.ValidatorUtil;
import tools.dynamia.domain.query.QueryConditions;
import tools.dynamia.domain.services.AbstractService;
import tools.dynamia.domain.services.CrudService;
import tools.dynamia.modules.security.domain.Profile;
import tools.dynamia.modules.security.domain.User;
import tools.dynamia.modules.security.domain.UserProfile;
import tools.dynamia.modules.security.services.ProfileService;
import tools.dynamia.modules.security.services.SecurityService;

import java.util.List;

/**
 * @author Mario Serrano Leones
 */


public class SecurityServiceImpl extends AbstractService implements SecurityService, UserDetailsService {


    private final ProfileService profileService;
    private final CrudService crudService;
    private final PasswordEncoder passwordEncoder;


    public SecurityServiceImpl(ProfileService profileService, CrudService crudService, PasswordEncoder passwordEncoder) {
        this.profileService = profileService;
        this.crudService = crudService;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    protected CrudService crudService() {
        return crudService;
    }


    @Override
    @PostConstruct
    public void checkAccountDefaultsSettings() {
        try {
            profileService.getDefaultProfile();
            profileService.getAdminProfile();
            createDefaultUser();

        } catch (Exception e) {
            log("Error checking account default settings ", e);
        }
    }

    @Override
    public User loadUserByUsername(String username) {
        User user = null;

        if (username.contains("@")) {
            user = crudService().findSingle(User.class, "email", QueryConditions.eq(username));
        }

        if (user == null) {
            user = crudService().findSingle(User.class, "username", QueryConditions.eq(username));
        }

        if (user != null) {
            return user;
        } else {
            throw new UsernameNotFoundException("Usuario " + username + " no encontrado");
        }
    }

    @Override
    @Transactional
    public User createUser(User usuario) {
        if (usuario.getId() == null) {
            String password = usuario.getPassword();

            usuario.setPassword(passwordEncoder.encode(password));
            usuario = crudService().create(usuario);
            UserProfile perfil = new UserProfile(profileService.getDefaultProfile(), usuario);
            perfil.setAccountId(usuario.getAccountId());
            crudService().create(perfil);
        }
        return usuario;
    }


    @Override
    public void validatePassword(String password, String rePassword) {

        ValidatorUtil.validateEmpty(password, "Enter user password");


        if (!password.equalsIgnoreCase(rePassword)) {
            throw new ValidationError("Password not matches");
        }
    }

    @Override
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void setNewPassword(String username, String currentPassword, String newPassword, String confirmPassword) {
        User user = loadUserByUsername(username);

        if (!passwordEncoder.matches(currentPassword, user.getPassword())) {
            throw new ValidationError("Current password is invalid");
        }

        validatePassword(newPassword, confirmPassword);

        if (newPassword.equals(currentPassword)) {
            throw new ValidationError("New password is equal to the current password");
        }

        user.setPassword(passwordEncoder.encode(newPassword));
        user.setPasswordExpired(false);
        crudService().update(user);
    }

    @Transactional
    public void createDefaultUser() {

        long count = crudService().count(User.class);
        if (count == 0) {

            User admin = new User();
            admin.setFullname("Administrator");
            admin.setUsername("admin");
            admin.setEmail("admin@admin.com");
            admin.setPassword("adminadmin");
            createUser(admin);
            UserProfile profile = new UserProfile(profileService.getAdminProfile(), admin);
            crudService().create(profile);
        }
    }


    @Override
    public User getUserByEmail(String email) {
        return crudService().findSingle(User.class, "email", QueryConditions.eq(email));
    }

    @Override
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void resetPassword(User user, String nuevo, String reNuevo) {
        validatePassword(nuevo, reNuevo);
        user.setPassword(passwordEncoder.encode(nuevo));
        crudService().update(user);
    }


    @Override
    public User getCurrentSessionUser() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null) {
            throw new SecurityException("No current user found");
        }
        return (User) auth.getPrincipal();
    }


    @Override
    public List<Profile> getProfilesByAccountId(Long accountId) {
        return crudService().find(Profile.class, "accountId", accountId);
    }


}
