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

/**
 * 시큐리티가 /login주소 요청이 오면 낚아채서 로그인을 진행시킨다.
 * /login경로에 대한 컨트롤러는 만들지 않이도 된다.
 * 로그인 진행이 완료되면 시큐리티가 session을 만들어준다 (security ContextHodler)
 * 세션에 들어갈 오브젝트는 정해져 있다 Authentication타입의 객체
 * <p>
 * Authentication 안에 user정보가 있어야 한다.
 * Security Session안에 Authentication오브젝트 안에 -> UserDetails(구현체 PrincipalDetail)
 */

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

    @Override
    public boolean isEnabled() {
        log.info("isEnabled");
        return true;
    }


    @Override
    public <A> A getAttribute(String name) {
        return OAuth2User.super.getAttribute(name);
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    @Override
    public String getName() {
        return (String) attributes.get("sub"); //별로 중요하진 않다.
    }

    //해당 User의 권한을 리턴하는 곳이다
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        log.info("getAuthorities");
        Collection<GrantedAuthority> collection = new ArrayList<>();
        collection.add(new GrantedAuthority() {
            @Override
            public String getAuthority() {
                return user.getRole();
            }
        });
        return collection;
    }

    @Override
    public String getPassword() {
        log.info("getPassword");
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        log.info("getUsername");
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        log.info("isAccountNonExpired");
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        log.info("isAccountNonLocked");
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        log.info("isCredentialsNonExpired");
        /** 1년동안 회원이 로그인을 안하면 휴면계정으로 하기로 함
         *  현재시간 - 로그인 시간 => 1년 초과인 경우 return false
         */
        return true;
    }


}
