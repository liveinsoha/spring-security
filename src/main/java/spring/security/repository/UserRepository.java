package spring.security.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import spring.security.model.User;

// JpaRepository 를 상속하면 자동 컴포넌트 스캔됨. @Repository 없어도 됌
public interface UserRepository extends JpaRepository<User, Long> {

    User findByUsername(String username);
}
