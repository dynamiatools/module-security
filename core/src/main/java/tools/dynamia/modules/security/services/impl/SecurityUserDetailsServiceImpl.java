package tools.dynamia.modules.security.services.impl;

import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import tools.dynamia.domain.query.QueryConditions;
import tools.dynamia.domain.services.AbstractService;
import tools.dynamia.integration.sterotypes.Service;
import tools.dynamia.modules.security.domain.User;

@Service
public class SecurityUserDetailsServiceImpl extends AbstractService implements UserDetailsService {


    @Override
    public User loadUserByUsername(String username) {
        log("Loading user by username: " + username);
        var user = crudService().findSingle(User.class, "username", QueryConditions.eq(username));

        if (user == null) {
            throw new UsernameNotFoundException("User with username " + username + " not found");
        }
        return user;
    }
}
