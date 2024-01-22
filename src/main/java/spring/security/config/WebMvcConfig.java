package spring.security.config;

import org.springframework.boot.web.servlet.view.MustacheViewResolver;
import org.springframework.web.servlet.config.annotation.ViewResolverRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

public class WebMvcConfig implements WebMvcConfigurer {

    @Override
    public void configureViewResolvers(ViewResolverRegistry registry) {
        MustacheViewResolver resolver = new MustacheViewResolver();
        resolver.setCharset("UTF-8");
        resolver.setContentType("text/html; charset=UTF-8");
        resolver.setPrefix("classpath:/templates/");
        resolver.setSuffix(".html");

        //뷰 리졸버의 세팅을 변경한다.
        /**
         * 인코딩은 UTF-8
         * 내가 뷰리졸버에 요청하는 건 html파일이고 UTF-8
         * 앞에 있는 경로는 classpath:는 프로젝트 경로라고 생각한다.
         */

        registry.viewResolver(resolver);
    }
}
