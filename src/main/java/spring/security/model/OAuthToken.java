package spring.security.model;

import lombok.Data;

@Data
public class OAuthToken {

    String access_token;
    String token_type;
    String refresh_token;
    String expires_in;
    String scope;
    String refresh_token_expires_in;
}
