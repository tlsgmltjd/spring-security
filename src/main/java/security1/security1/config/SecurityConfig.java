package security1.security1.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration // 빈으로 등록
@EnableWebSecurity // 스프링 시큐리티 필터가 스프링 필터체인에 등록이 된다.
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true) // secured 어노테이션 활성화, preAuthorize, postAuthorize 어노테이션 활성화
public class SecurityConfig {

    // 해당 메서드의 리턴되는 오브젝트를 IoC로 등록해준다.
    @Bean
    public BCryptPasswordEncoder encoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.authorizeRequests()
                .requestMatchers("/user/**").authenticated() // 로그인 한 사람들만
                .requestMatchers("/manager/**").access("hasAnyRole('ROLE_MANAGER','ROLE_ADMIN')") // 로그인을 했지만 매니저나 어드민 권한
                .requestMatchers("/admin/**").access("hasRole('ROLE_ADMIN')") // 로그인으르 했지만 어드민 권한
                .anyRequest().permitAll() // 이외의 요청은 모든 사람에게 권한 허용
                .and()
                .formLogin()
                .loginPage("/loginForm")
                .loginProcessingUrl("/login") // login이라는 주소가 호출이 되면 시큐리티가 낚아채서 대신 로그인을 진행해줌
                .defaultSuccessUrl("/")
                .and()
                .oauth2Login()
                .loginPage("/loginForm"); // 구글 로그인이 완료된 뒤에 후처리가 필요하다!

        return http.build();
    }
}