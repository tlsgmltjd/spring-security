package security1.security1.config.oauth;

import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    // 구글로 부터 받은 userRequest 데이터에 대한 후처리가되는 함수
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        System.out.println("userRequest : " + userRequest.getClientRegistration());
        System.out.println("userRequest : " + userRequest.getAccessToken().getTokenValue());

        // userRequest : {sub=111653458897920661963 <- Primary key 같은거, name=희성신, given_name=신, family_name=희성, picture=https://lh3.googleusercontent.com/a/ACg8ocKU98UCX9K3GETfjXL-eWH_dMopBcNkQySpuYAVfPszLg=s96-c, email=s23012@gsm.hs.kr, email_verified=true, locale=ko, hd=gsm.hs.kr}
        // username = "google_111653458897920661963"
        // password = "암호화 (겟인데어)" <- 이걸로 로그인 할거기 때문에 null만 아니고 아무거나 가능
        // email = "s23012@gsm.hs.kr"
        // role = "ROLE_USER"
        // provider = "google"
        // providerId = "111653458897920661963"

        // 이 정보로 회원가입을 ㄱㄱ
        System.out.println("userRequest : " + super.loadUser(userRequest).getAttributes());
        return super.loadUser(userRequest);
    }
}
