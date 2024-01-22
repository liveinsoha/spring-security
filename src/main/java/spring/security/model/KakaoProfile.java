package spring.security.model;


import lombok.Data;

@Data
public class KakaoProfile {

    public Long id;
    public String connected_at;
    public Properties properties;
    public KakaoAccount kakao_account;

    @Data
    public static class Properties {

        public String nickname;
    }

    @Data
    public static class KakaoAccount {

        public Boolean profile_nickname_needs_agreement;
        public Profile profile;

        @Data
        public static class Profile {

            public String nickname;

        }

    }

}



