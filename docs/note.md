````agsl
package spring.security.config.oauth;

import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    // 구글로 부터 받은 userRequest 대이터에 대한 후처리 되는 함수
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        System.out.println("userRequest = " + userRequest);
        System.out.println("userRequest.getClientRegistration() = " + userRequest.getClientRegistration());//registrationId로 어떤 OAuth로그인인지 확인 가능 -> 'google'
        System.out.println("userRequest.getAccessToken().getTokenValue() = " + userRequest.getAccessToken().getTokenValue());
        /**
         * 구글 로그인 버튼 클랙 -> 구글로그인 창 -> 로그인 완료 -> Code리턴(OAuth2-Client라이브러리) -> AccessToken요청
         * // UserRequest 정보 -> loadUser함수 호출(구글로부터 회원 프로필 받을 수 있다)
         */
        System.out.println("super.loadUser(userRequest).getAttributes() = " + super.loadUser(userRequest).getAttributes());
        return super.loadUser(userRequest);
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
````
구글로그인을 완료할경우 후처리 되는 함수이다.
DefaultOAuth2UserService를 상속하고 loadUser를 오버라이딩하여 구현한다.
userRequest를 파라미터로 받고 super.loadUser(userRequest)를 하면
userRequest로부터 구글개인 정보를 받을 수 있다 -> 이 정보를 가지고 강제 회원가입을 진행한다.

````agsl
  @GetMapping("/test/login")
    @ResponseBody
    public String testLogin(Authentication authentication, @AuthenticationPrincipal PrincipalDetails userDetails) {
        //로그인 했을 경우 스프링 시큐리티는 Authentication객체를 넘겨줄 수 있다
        System.out.println("/test/login ==========");
        System.out.println("authentication.getPrincipal() = " + authentication.getPrincipal());
        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();

        //@AuthenticationPrincipal 어노테이션으로 세션 정보에 접근하여 Authentication안에 있는 UserDetail 받을 수 있다.
        System.out.println("userDetails = " + userDetails.getUser());
        return "세션 정보 확인하기";
    }
````
- 로그인 상태인 경우 Authentication객체를 넘겨 받을 수 있고(DI의존성 주입) 안에 있는 
UserDetail의 구현체 PrincipalDetail에 접근할 수 있다.
로그인 하지 않은 경우 UserDetail은 비어 있다 -> getPrincipal()하면 nullPointerException

- @AuthenticationPrincipal 어노테이션으로 세션 정보에 접근하여 Authentication안에 있는 UserDetail 받을 수 있다.
UserDetails의 구현체로 PricipalDetails가 있으므로 다운 캐스팅 하여 파라미터로 받을 수 있고 PrincipalDetails 필드에 있는 
User에 접근할 수 있다(getUser())

````agsl
@GetMapping("/test/oauth/login")
    @ResponseBody
    public String testOAuthLogin(Authentication authentication, @AuthenticationPrincipal OAuth2User oauth) {
        //로그인 했을 경우 스프링 시큐리티는 Authentication객체를 넘겨줄 수 있다
        System.out.println("/test/login ==========");
        System.out.println("authentication.getPrincipal() = " + authentication.getPrincipal());
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        System.out.println("oauth = " + oauth.getAttributes());

        //구글 로그인으로 진행 한 경우 OAuth2User객체()를 Authentication안에 가지고 있다.
        System.out.println("userDetails.getUser = " + oAuth2User.getAttributes());
        return "세션 정보 확인하기";
    }
````

- 하지만 구글 로그인으로 로그인 한 경우 PrincipaDetials를 받을 수 없다.
- 구글 로그인으로 진행 한 경우 OAuth2User객체()를 Authentication안에 가지고 있다.
- @AuthenticationPrincipal 애노테이션으로 받아 바로 활용할 수 있다.

- 스프링 시큐리티는 원래 세션 안에 시큐리티가 관리하는 세션을 따로 가지고 있다
- 스프링 시큐리티 세션에 들어갈 수 있는 객체는 Authentication 밖에 없다.
- 따라서 컨트롤러에서는 해당 Authentication을 DI할 수 있다.
- Authentication안에 들어갈 두가지 타입이 있는데 1. userDetails(일반 로그인) 2.OAuth2User(OAuth로그인)
- 불편한 점이 있다. 일반적인 로그인 할 경우와 OAuth로그인을 할 경우 받을 수 있는 타입이 다르다는 점이다.
- 해결책은 클래스X(PrincipalDetails는) 를 만들어 UserDetails도 구현하고 OAuth2User도 구현하여 X를 활용한다.
-> PrincipalDetails는 UserDetails를 구현하고 있으니 OAuth2User도 구현하여 활용하자.


### 섹션 1-4
- PrincipalDetails를 구현한 이유는 아래와 같다.
- 회원가입을 진행하기 위해 필요한 타입은 User객체이다. 
- 근데 시큐리티 세션의 오브젝트인 Authentication 내에 있을 수 있는 2가지 오브젝트 UserDetails, OAuth2User는 User를 포함하고 있지 않다
- 따라서 PrincipalDetails 클래스를 만들고 두 오브젝트를 implements 하고 User객체를 품고 있도록 하였다

- 따라서 이제 PrincipalDetails 가 두 오브젝트를 모두 구현했으므로 활용할 수 있고, User객체 또한 가지고 있다 .

구글 로그인을 한 경우 
{sub=101142878977861600605, name=이원준, given_name=원준, family_name=이, picture=https://lh3.googleusercontent.com/a/ACg8ocKt7IIPr1uqwoL1R2zH-vUKaBu4bcvPLZUexRp7bmMX=s96-c, email=wonjun88888@gmail.com, email_verified=true, locale=ko}
OAuth2User객체는 getAttributes에 이 정보를 들고 있다. -> 이 정보를 가지고 User객체를 만들어 회원가입을 진행하려고 한다.


````agsl
String registrationId = userRequest.getClientRegistration().getRegistrationId(); //google
String providerId = oAuth2User.getAttribute("sub");
String username = registrationId + "_" + providerId; //아이디와 비번은 로그인 시 의미는 없지만 user객체를 만들기 위해 생성한다
String password = passwordEncoder.encode("겟인데어");
String email = oAuth2User.getAttribute("email");
String role = "ROLE_USER";
return super.loadUser(userRequest);
/*
````
구글 로그인 후 후처리를 하는 곳에 회원가입 로직이 있다.
무작정 가입을 시키는 건 아니고 회원 가입이 되어있을 수도 있으니 분기한다

````agsl
package spring.security.auth;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;
import spring.security.model.User;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

@Slf4j
@Data
public class PrincipalDetails implements UserDetails, OAuth2User {

    private User user;
    private Map<String, Object> attributes;


    //일반 로그인의 경우 사용하는 생성자
    public PrincipalDetails(User user) {
        this.user = user;
    }

    //OAuth 로그인의 경우 사용하는 생성자
    public PrincipalDetails(User user, Map<String, Object> attributes) {
        this.user = user;
        this.attributes = attributes;
    }

   ...

````



````agsl
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
        System.out.println("userRequest.getClientRegistration() = " + userRequest.getClientRegistration());//registrationId로 어떤 OAuth로그인인지 확인 가능 -> 'google'
        System.out.println("userRequest.getAccessToken().getTokenValue() = " + userRequest.getAccessToken().getTokenValue());
        /**
         * 구글 로그인 버튼 클랙 -> 구글로그인 창 -> 로그인 완료 -> Code리턴(OAuth2-Client라이브러리) -> AccessToken요청
         * // UserRequest 정보 -> loadUser함수 호출(구글로부터 회원 프로필 받을 수 있다)
         */
        OAuth2User oAuth2User = super.loadUser(userRequest);
        System.out.println("super.loadUser(userRequest).getAttributes() = " + super.loadUser(userRequest).getAttributes());


        String provider = userRequest.getClientRegistration().getRegistrationId(); //google
        String providerId = oAuth2User.getAttribute("sub");
        String username = provider + "_" + providerId; //아이디와 비번은 로그인 시 의미는 없지만 user객체를 만들기 위해 생성한다
        String password = passwordEncoder.encode("겟인데어");
        String email = oAuth2User.getAttribute("email");
        String role = "ROLE_USER";


        User userEntity = userRepository.findByUsername(username);
        if(userEntity == null){ //없는 회원인 경우 회원 강비을 시킨다.
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
````

- 구글로그인을 진행한 경우 후처리 메소드에서 User와 attributes를 생성자로 넘긴다. 회원가입 혹은 로그인 처리를 진행한다.
- 일반 로그인인 경우 User만 생성자로 넘긴다

````agsl
@Controller //view 리턴
@RequiredArgsConstructor //Secured 애노테이션을 활성화 한다
public class IndexController {

    /*
    user, login은 로그인 한 사용자만, manager, admin은 권한이 있는 사용자만 접근을 가능하게 하고 싶다.
     */
    private final BCryptPasswordEncoder passwordEncoder;
    private final UserRepository userRepository;

...

    @ResponseBody
    @GetMapping("/user")
    public String user(@AuthenticationPrincipal PrincipalDetails principalDetails) {
        System.out.println("principalDetails.getUser() = " + principalDetails.getUser());
        return "user";
    }//어떤 로그인을 하든 이 경로로 PrincipalDetails을 받을 수 있다.

  ...
}


````
- 이제 일반적인 로그인을 한 경우와 구글 로그인을 한 경우 모두@AuthenticationPrincipal 을 통해 PrincipalDetails를 파라미터로 받을 수 있다.
  principalDetails.getUser() = User(id=5, username=google_101142878977861600605, password=$2a$10$gn8oZs.KQ97A.TsvlF.IHulp8qjEIersckepJpoxjbelTuvBYR/4a, email=wonjun88888@gmail.com, role=ROLE_USER, provider=google, providerId=101142878977861600605, createdDate=null)
 principalDetails.getUser() = User(id=2, username=admin, password=$2a$10$igLoDgwiRToFiSDvTp0sm.fT8EZYwIHItoj9HKYeSJMU/6O.BMd9., email=asd@naver.com, role=ROLE_ADMIN, provider=null, providerId=null, createdDate=null)
- 이제 어떤 로그인을 하든 상관없이 분기하지 않고 @AuthenticationPrincipal 애노테이션으로 User를 받을 수 있다.
- 
두 가지 경우가 있다 
우리가 굳이 오버라이딩 하지 않아도
일반로그인인 경우 UserDetailsServiced의 loadUserByUsername이 실행되고 구글로그인인 경우
DefaultOAuth2UserService의 loadUser가 실행 된다.

우리가 구현체를 Service 구현하여 오버라이딩을 하는 이유는 각각의 loadUserByUsername, loadUser에서 리턴 되는 오브젝트가
PrincipalDetails로 통일할 수 있기 때문이다. PrincipalDetails는 OAuth2User, UserDetails를 모두 구현하고 있기 때문이다.
그리고 loadUserByUsername, loadUserByUsername이 종료 될 때 @AuthenticationPrincipal 애노테이션이 활성화 된다.


# 구글과 페이스북의 경우 attributes로 넘어오는 속성의 이름이 다르기 때문에
OAuth2UserInfo라는 인터페이스를 만들어 구현한다.
구글은 sub이고 페이스북은 id이다

````agsl
package spring.security.config.oauth;

public interface OAuth2UserInfo {

    String getEmail();

    String getName();

    String getProvider();

    String getProviderId();
}
````

````agsl
public class GoogleUserInfo implements OAuth2UserInfo {
    private Map<String, Object> attributes;

    public GoogleUserInfo(Map<String, Object> attributes) {
        this.attributes = attributes;
    }

    @Override
    public String getEmail() {
        return (String) attributes.get("email");
    }

    @Override
    public String getName() {
        return (String) attributes.get("name");
    }

    @Override
    public String getProvider() {
        return (String) attributes.get("sub");
    }

    @Override
    public String getProviderId() {
        return "google";
    }
}

````

````agsl
public class FacebookUserInfo implements OAuth2UserInfo {

    private Map<String, Object> attributes;

    public FacebookUserInfo(Map<String, Object> attributes) {
        this.attributes = attributes;
    }

    @Override
    public String getEmail() {
        return (String) attributes.get("email");
    }

    @Override
    public String getName() {
        return (String) attributes.get("name");
    }

    @Override
    public String getProvider() {
        return (String) attributes.get("id");
    }

    @Override
    public String getProviderId() {
        return "facebook";
    }
}
````

````agsl
   OAuth2UserInfo oAuth2UserInfo = null;

        if (oAuth2User.getAttributes().get("providerId").equals("google")) {
            oAuth2UserInfo = new GoogleUserInfo(oAuth2User.getAttributes());
        } else if (oAuth2User.getAttributes().get("providerId").equals("facebook")) {
            oAuth2UserInfo = new FacebookUserInfo(oAuth2User.getAttributes());
        } else {
            System.out.println("구글과 페이스북만 지원");
        }
        
              String provider = oAuth2UserInfo.getProvider();
        String providerId = oAuth2UserInfo.getProviderId();
        String username = provider + "_" + providerId;
        String password = passwordEncoder.encode("겟인데어");
        String email = oAuth2User.getAttribute("email");
        String role = "ROLE_USER";
````

이와 같이 리팩토링을 하면 유지보수하는 데 도움이 된다. 네이버로그인을 구현할 경우에도 OAuthUserinfo를 구현할 수 있기 때문이다
스프링 부트로 기본 로그인 + OAuth2.0로그인 통합하여 구현을 했다.








