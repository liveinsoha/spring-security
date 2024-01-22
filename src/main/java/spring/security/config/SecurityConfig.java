package spring.security.config;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import spring.security.config.oauth.PrincipalOauth2UserService;

import java.security.Principal;

/**
 * 블로그 예제에서 카카오로그인은 다음과 같았다.
 * 1. 코드 받기(인증), 2. 액세스 토큰(권한), 3. 사용자 프로필 정보를 가져오고
 * 4-1. 그 정보를 토대로 회원가입을 자동으로 진행시키키도 함.
 * 4-2 회원정보가 모자랄 경우 (집주소) -> 쇼핑몰 추가적인 회원 가입 폼
 */


@Configuration
@EnableWebSecurity
@EnableMethodSecurity(securedEnabled = true, prePostEnabled = true) //Secur e애노테이션 활성화
public class SecurityConfig {

    @Autowired
    private PrincipalOauth2UserService principalOauth2UserService;


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(CsrfConfigurer::disable); //SecurityConfig파일 작동 안하여 lonin을 이제 낚아채지 않는다.
        http.authorizeHttpRequests(authorize ->
                                authorize.requestMatchers("/user/**").authenticated() //인증만 되면 둘어갈 수 있는 주소다
                                        .requestMatchers("/admin/**").hasAnyRole("ADMIN", "MANAGER")
                                        .requestMatchers("/manager/**").hasAnyRole("MANAGER")
                                        .anyRequest().permitAll()

                        //권한이 없는 경로로 접근할 때 로그인(/login) 페이지로 이동하고 싶다.
                        //3개를 제외하면 아무 권한 없이 접근이 가능하다.
                        //접근권한이 없는 경우 403이 발생
                )
                .formLogin(formLogin ->
                        formLogin
                                .loginPage("/loginForm")
                                .usernameParameter("username") //html의 name속성 쿼리파라미터 요청,,
                                .passwordParameter("password") //
                                .loginProcessingUrl("/login") // /login 주소가 호출되면 시큐리티가 낚아채서 대신 로그인을 진행한다
                                .defaultSuccessUrl("/") //로그인 성공시에 home으로 이동한다.
                ).oauth2Login(oauth ->
                        oauth
                                .loginPage("/loginForm")
                                .userInfoEndpoint(endpoint -> endpoint.userService(principalOauth2UserService))
                );

        /**
         * Tip
         * //구글 로그인이 완료딘 뒤의 후처리.
         * AuthClient 라이브러리는 코드를 내어주는 게 아닌 (액세스 토큰 + 사용자 프로필 정보) 줌
         */
//일반적인 로그인 페이지나 oauth로그인 페이지 같게 설정


        return http.build();
    }

    /**
     * @Bean 어노테이션: 이 어노테이션은 해당 메서드가 빈(Bean)을 생성하는 메서드임을 나타냅니다. 스프링 컨테이너에서 이 빈을 사용할 수 있습니다.
     * SecurityFilterChain filterChain(HttpSecurity http) throws Exception: 이 메서드는 SecurityFilterChain을 반환하고, HttpSecurity 객체를 매개변수로 받습니다. HttpSecurity는 Spring Security의 주요 구성 클래스 중 하나로, 보안 설정을 구성하는 데 사용됩니다.
     * http.csrf(CsrfConfigurer::disable): CSRF(Cross-Site Request Forgery) 보호를 비활성화합니다. 이것은 간단한 예제이므로 CSRF 보호를 해제했습니다. 실제 프로덕션 환경에서는 적절한 CSRF 보호를 사용해야 할 수 있습니다.
     * http.authorizeHttpRequests(authorize -> ...): 이 메서드는 요청에 대한 권한 부여 규칙을 정의합니다. 각 규칙은 authorize.requestMatchers()를 사용하여 특정 요청 패턴에 대한 권한을 설정합니다.
     * /user/** 패턴에 대한 요청은 인증된 사용자만 허용합니다.
     * /admin/** 패턴에 대한 요청은 "ADMIN" 또는 "MANAGER" 역할을 가진 사용자만 허용합니다.
     * /manager/** 패턴에 대한 요청은 "MANAGER" 역할을 가진 사용자만 허용합니다.
     * 다른 모든 요청은 모든 사용자에게 허용됩니다.
     * return http.build(): 최종적으로 구성된 HttpSecurity 객체를 반환합니다. 이를 통해 보안 필터 체인이 구성되어 애플리케이션에 적용됩니다.
     */
}
