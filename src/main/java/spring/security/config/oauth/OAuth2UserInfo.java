package spring.security.config.oauth;

public interface OAuth2UserInfo {

    String getEmail();

    String getName();

    String getProvider();

    String getProviderId();
}
