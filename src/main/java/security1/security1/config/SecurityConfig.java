package security1.security1.config;

// 1. 코드받기(인증)
// 2. 엑세스토큰(권한)
// 3. 사용자 프로필 정보를 가져옴
// 4-1. 그 정보를 토대로 회원가입을 자동을 진행시키기도 함
// 4-2. (이메일, 전화번호, 이름, 아이디) ex. 쇼핑몰 -> (집주소) 추가 정보가 필요하면 추가정보 회원가입창

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import security1.security1.config.oauth.PrincipalOauth2UserService;

@Configuration // 빈으로 등록
@EnableWebSecurity // 스프링 시큐리티 필터가 스프링 필터체인에 등록이 된다.
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true) // secured 어노테이션 활성화, preAuthorize, postAuthorize 어노테이션 활성화
public class SecurityConfig {

    @Autowired
    private PrincipalOauth2UserService principalOauth2UserService;

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
                .loginPage("/loginForm")
                .userInfoEndpoint()
                .userService(principalOauth2UserService); // 구글 로그인이 완료된 뒤에 후처리가 필요하다! Tip. 코드X (엑세스토큰+사용자프로필정보)
        ;

        return http.build();
    }
}