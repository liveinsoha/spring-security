package spring.security.auth;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Repository;
import org.springframework.stereotype.Service;
import spring.security.model.User;
import spring.security.repository.UserRepository;

/**
 * 시큐리티 설정에서 loginProcessingUrl("/login) 설정함
 * login 요청이 들어오면 자동으로 UserDetailsService 타입으로 Ioc되어 있는 loaUserByUsername 함수가 실행된다
 */
@Service //서비스 등록
@RequiredArgsConstructor
@Slf4j
public class PrincipalDetailsService implements UserDetailsService {

    private final UserRepository userRepository;


    /**
     * 이름으로 DB에서 조회 후 엔티티가 존재하는 경우에 PrincipalDetails를 리턴한다.
     * 시큐리티 세션(Authentication(내부 UserDetails))
     *
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User userEntity = userRepository.findByUsername(username);
        if (userEntity != null) {
            log.info("로그인 하자");
            return new PrincipalDetails(userEntity); //이게 Authentication안에 들어간다.
        }
        return null;
    }
}
