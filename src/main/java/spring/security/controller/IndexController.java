package spring.security.controller;


import lombok.RequiredArgsConstructor;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import spring.security.auth.PrincipalDetails;
import spring.security.model.User;
import spring.security.repository.UserRepository;

@Controller //view 리턴
@RequiredArgsConstructor //Secured 애노테이션을 활성화 한다
public class IndexController {

    /*
    user, login은 로그인 한 사용자만, manager, admin은 권한이 있는 사용자만 접근을 가능하게 하고 싶다.
     */
    private final BCryptPasswordEncoder passwordEncoder;
    private final UserRepository userRepository;


    @GetMapping({"", "/"})
    public String index() {
        return "index";
    }

    @ResponseBody
    @GetMapping("/user")
    public String user(@AuthenticationPrincipal PrincipalDetails principalDetails) {
        System.out.println("principalDetails.getUser() = " + principalDetails.getUser());
        return "user";
    }

    @ResponseBody
    @GetMapping("/manager")
    public String manager() {
        return "manager";
    }

    /**
     * 패스워드를 암호화 하지 않으면 시큐리티로 로그인을 할 수 없다
     */

    @PostMapping("/join")
    public String join(@ModelAttribute User user) {
        System.out.println("user = " + user);
        String rawPassword = user.getPassword();
        String encoded = passwordEncoder.encode(rawPassword);
        user.setPassword(encoded);
        user.setRole("ROLE_USER");//null이면 안댐
        userRepository.save(user);

        return "redirect:/loginForm";
    }

    //스프링 시큐리티가 해당 경로를 낚아챈다

    @GetMapping("/loginForm")
    public String loginForm() {
        return "loginForm";
    }

    @GetMapping("/info")
    @ResponseBody
    @Secured("ROLE_ADMIN")
    public String info() {
        return "개인정보";
    }

    @GetMapping("/data")
    @ResponseBody
    @PreAuthorize("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
    /**
     * PreAuthorize PostAuthorize 쓸 일이 잘 없다.
     * 특정 메소드에만 걸고 싶을 때 Secured. 글로벌로 걸고 싶을 때 SecurityConfig 사용
     */
    public String date() {
        return "데이터";
    }

    @GetMapping("/test/login")
    @ResponseBody
    public String testLogin(Authentication authentication, @AuthenticationPrincipal PrincipalDetails userDetails) {
        //로그인 했을 경우 스프링 시큐리티는 Authentication객체를 넘겨줄 수 있다
        System.out.println("/test/login ==========");
        System.out.println("authentication.getPrincipal() = " + authentication.getPrincipal());
        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();

        //@AuthenticationPrincipal 어노테이션으로 세션 정보에 접근하여 Authentication안에 있는 UserDetail 받을 수 있다.
        System.out.println("userDetails.getUser = " + userDetails.getUser());
        return "세션 정보 확인하기";
    }

    @GetMapping("/test/oauth/login")
    @ResponseBody
    public String testOAuthLogin(Authentication authentication, @AuthenticationPrincipal OAuth2User oauth) {
        //로그인 했을 경우 스프링 시큐리티는 Authentication객체를 넘겨줄 수 있다
        System.out.println("/test/login ==========");
        System.out.println("authentication.getPrincipal() = " + authentication.getPrincipal());
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();


        //구글 로그인으로 진행 한 경우 OAuth2User객체()를 Authentication안에 가지고 있다.
        System.out.println("userDetails.getUser = " + oAuth2User.getAttributes());
        System.out.println("oauth = " + oauth.getAttributes());
        return "세션 정보 확인하기";
    }

    @ResponseBody
    @GetMapping("/admin")
    public String admin() {
        return "admin";
    }


    @GetMapping("/joinForm")
    public String joinForm() {
        return "joinForm";
    }

    @ResponseBody
    @GetMapping("/joinProc")
    public String joinProc() {
        return "회원가입 완료됨!";
    }
}
