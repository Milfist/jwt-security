package es.milfist.usuario;

import static es.milfist.security.Constants.ROLE_SEPARATOR;
//TODO: Refactor
public class UserCreator {

    public static User transformStringCredentialsToUsuario(String decodedCredentials) {
        String[] credentialsArray = decodedCredentials.split(":");
        User user = new User();
        user.setUsername(credentialsArray[0]);
        user.setPassword(credentialsArray[1]);
        return user;
    }

    public static User getUsuarioFromDecodeInformation(String decodeInformation) {

        String[] userAndRoles = decodeInformation.split(":");
        User user = new User();

        user.setUsername(userAndRoles[0]);

        String[] roles = userAndRoles[1].split(ROLE_SEPARATOR);

        user.setRole(roles[0]);
        return user;
    }



}
