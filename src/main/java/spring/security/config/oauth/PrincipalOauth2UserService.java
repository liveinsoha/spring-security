package spring.security.config.oauth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import spring.security.auth.PrincipalDetails;
import spring.security.model.User;
import spring.security.repository.UserRepository;

import java.util.Map;

@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    @Autowired
    BCryptPasswordEncoder passwordEncoder;

    @Autowired
    UserRepository userRepository;

    // 구글로 부터 받은 userRequest 대이터에 대한 후처리 되는 함수
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        System.out.println("userRequest = " + userRequest);
        System.out.println("userRequest.getClientRegistration().getRegistrationId() = " + userRequest.getClientRegistration().getRegistrationId());//registrationId로 어떤 OAuth로그인인지 확인 가능 -> 'google'
        System.out.println("userRequest.getAccessToken().getTokenValue() = " + userRequest.getAccessToken().getTokenValue());
        /**
         * 구글 로그인 버튼 클랙 -> 구글로그인 창 -> 로그인 완료 -> Code리턴(OAuth2-Client라이브러리) -> AccessToken요청
         * // UserRequest 정보 -> loadUser함수 호출(구글로부터 회원 프로필 받을 수 있다)
         */
        OAuth2User oAuth2User = super.loadUser(userRequest);
        System.out.println("oAuth2User.getAttributes() = " + oAuth2User.getAttributes());

        OAuth2UserInfo oAuth2UserInfo = null;

        if (userRequest.getClientRegistration().getRegistrationId().equals("google")) {
            oAuth2UserInfo = new GoogleUserInfo(oAuth2User.getAttributes());
        } else if (userRequest.getClientRegistration().getRegistrationId().equals("facebook")) {
            oAuth2UserInfo = new FacebookUserInfo(oAuth2User.getAttributes());
        } else if (userRequest.getClientRegistration().getRegistrationId().equals("naver")) {
            oAuth2UserInfo = new NaverUserInfo((Map)oAuth2User.getAttributes().get("response"));
        } else {
            System.out.println("구글과 페이스북만 네이버만 지원");
        }

      /*  String provider = userRequest.getClientRegistration().getRegistrationId(); //google
        String providerId = oAuth2User.getAttribute("sub");
        String username = provider + "_" + providerId; //아이디와 비번은 로그인 시 의미는 없지만 user객체를 만들기 위해 생성한다
        String password = passwordEncoder.encode("겟인데어");
        String email = oAuth2User.getAttribute("email");
        String role = "ROLE_USER";*/

        String provider = oAuth2UserInfo.getProvider();
        String providerId = oAuth2UserInfo.getProviderId();
        String username = provider + "_" + providerId;
        String password = passwordEncoder.encode("겟인데어");
        String email = oAuth2User.getAttribute("email");
        String role = "ROLE_USER";


        User userEntity = userRepository.findByUsername(username);
        if (userEntity == null) { //없는 회원인 경우 회원 강비을 시킨다.
            userEntity = User.builder()
                    .username(username)
                    .password(password)
                    .email(email)
                    .role(role)
                    .provider(provider)
                    .providerId(providerId)
                    .build();
            userRepository.save(userEntity);
        }

        return new PrincipalDetails(userEntity, oAuth2User.getAttributes());
        /*
       이미 개인정보를 반환받을 수 있기 떄문에  액세스 토큰은 필요가 없다
       sub는 구글에서 사용자의 primary key같은 것.

       super.loadUser(userRequest).getAttributes())의 정보로 강제 회원 가입을 진행한다.

       username = google_sub 101142878977861600605
       password = "암호화(겟인데어)" 이 비번은 직접 쳐서 로그인 할 것이 아니기 때문에 뭐든 상관 없다
       emain = 구글 개인 정보 이메일
       role = "ROLE_USER"
       provider = "google"
       providerId = google_sub "101142878977861600605"


         */ //있으나 없으나(회원 가입 시킨다.) PrincipalDetails에 넣어 리턴한다

    }
}
