package spring.security.api;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.client.RestTemplate;
import spring.security.model.KakaoProfile;
import spring.security.model.OAuthToken;
import spring.security.model.User;
import spring.security.service.UserService;

import java.util.UUID;

@Controller
@Slf4j
@RequiredArgsConstructor
public class UserController {

    /**
     * application.yml 파일에 정의된 설정 값을 Spring Boot 애플리케이션에서 사용하려면,
     *
     * @Value 어노테이션을 사용하여 해당 값을 주입할 수 있습니다.
     * 주어진 예시에 따르면, cos 섹션의 key 값을 주입하려면 다음과 같이 할 수 있습니다.
     */
    @Value("${cos.key}")
    private String cosKey;

    private final UserService userService;

    //code를 쿼리스트링으로 넘기기 때문에 받아보자
    // 이 코드 값을 바탕으로 액세스 토큰을 발급받자. 로그인한 사용자의 개인정보에 접근하기 위해서
    @GetMapping("/auth/kakao/callback")
    public String kakaoCallback(String code) {

        //POST 방식으로 key=value 데이터를 요청
        //Post 요청을 하는 다양한 라이브러리가 있다 Retrofit(안드로이드), OkHttp, RestTempate
        RestTemplate restTemplate = new RestTemplate();


        //Haeder 오브젝트 생성
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add("Content-type", "application/x-www-form-urlencoded;charset=utf-8");

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "authorization_code");
        params.add("client_id", "d4767dbfadeb0bc96b02d1e7c6f06b09");
        params.add("redirect_uri", "http://localhost:8080/auth/kakao/callback");
        params.add("code", code);


        //HttpHeader와 HttpBody를 하나의 오브젝트에 담는다
        HttpEntity<MultiValueMap<String, String>> kakaoTokenRequest = new HttpEntity<>(params, httpHeaders);

        //Http요청하기 그리고 response 변수의 응답 받음.
        ResponseEntity<String> responseEntity = restTemplate.exchange("https://kauth.kakao.com/oauth/token", HttpMethod.POST, kakaoTokenRequest, String.class);
        /**
         * RestTemplate의 exchange 메서드를 사용하여 POST 요청을 보냅니다. 이 메서드는 URL,
         * HTTP 메서드, 요청 엔티티, 그리고 응답을 받을 데이터 타입을 인자로 받습니다.
         */
        //변수 만들어서 사용하자
        OAuthToken oAuthToken = null;
        //Gson, Json, ObjectMapper  -> 지원하는 라이브러리

        ObjectMapper objectMapper = new ObjectMapper();
        try {
            oAuthToken = objectMapper.readValue(responseEntity.getBody(), OAuthToken.class);
            /**
             * 파싱할 때 이름이 다르거나, getter setter가 없는 경우 예외가 발생한다. ()
             */
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }

        RestTemplate restTemplate2 = new RestTemplate();

        HttpHeaders httpHeaders2 = new HttpHeaders();
        httpHeaders2.add("Authorization", "Bearer " + oAuthToken.getAccess_token());
        httpHeaders2.add("Content-type", "application/x-www-form-urlencoded;charset=utf-8");


        HttpEntity<MultiValueMap<String, String>> kakaoProfileRequest2 = new HttpEntity<>(httpHeaders2); //헤더만 가지고 요청헤더를 만들 수 있다.
        ResponseEntity<String> responseEntity2 = restTemplate2.exchange("https://kapi.kakao.com/v2/user/me", HttpMethod.POST, kakaoProfileRequest2, String.class);

        log.info("응답 받음");
        System.out.println("responseEntity2.getBody() = " + responseEntity2.getBody());
        //Json데이터로 회원 정보가 넘어온다 id, 이름, email 등등
        KakaoProfile kakaoProfile = null;
        try {
            //응답 객체로 부터 json 데이터를 얻고 객체에 매핑한다.
            kakaoProfile = objectMapper.readValue(responseEntity2.getBody(), KakaoProfile.class);
            /**
             * 파싱할 때 이름이 다르거나, getter setter가 없는 경우 예외가 발생한다. ()
             */
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }


        //매핑한 객체로 부터 필요한 정보들을 골라서 DB에 저장한다.
        System.out.println("kakaoProfile.getId() = " + kakaoProfile.getId());
        System.out.println("kakaoProfile.getProperties().getNickname() = " + kakaoProfile.getProperties().getNickname());
        System.out.println("블로그 서버 유저네임 = " + kakaoProfile.getProperties().getNickname() + "_" + kakaoProfile.getId());
        // UUID garbagePassword = UUID.randomUUID();//비번이 필요 없어 uuid를 쓰지만 매번 바뀌기 때문에 다음에 로그인할 때 문제가 된다

        System.out.println("블로그 서버 패스워드 = " + cosKey);

        String username = kakaoProfile.getProperties().getNickname() + "_" + kakaoProfile.getId();
        //String password = garbagePassword.toString();

        User user = User.builder()
                .username(username)
                .password(cosKey)
                .build();

        User findUser = userService.findByUsername(user.getUsername());
        if (findUser != null) {
            //기존 회원 로그인 처리
        }

        //회원 가입 처리.
        log.info("로그인 진행");
        userService.join(user);


        return "redirect:/";
    }
}


