package tools.dynamia.modules.security.ui.listeners;

import tools.dynamia.app.ApplicationUserInfo;
import tools.dynamia.integration.sterotypes.Listener;
import tools.dynamia.modules.security.domain.User;
import tools.dynamia.modules.security.listeners.LoginListener;

@Listener
public class SetupApplicationUserInfoListener implements LoginListener {
    @Override
    public void onLoginSuccess(User user) {
        try {
            ApplicationUserInfo userInfo = ApplicationUserInfo.get();
            userInfo.setId(user.getId());
            userInfo.setUid(user.getUuid());
            userInfo.setDate(user.getCreationDate());
            userInfo.setEmail(user.getEmail());
            userInfo.setFullName(user.getFullname());
            userInfo.setUsername(user.getUsername());
            userInfo.setProfilePath("system/seguridad/miPerfil");


            if (user.getPhoto() != null) {
                userInfo.setImage(user.getPhoto().toURL());
            }
        } catch (Exception e) {

        }
    }
}
