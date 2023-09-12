package security1.security1.config.oauth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import security1.security1.config.CustomBCryptPasswordEncoder;
import security1.security1.config.auth.PrincipalDetails;
import security1.security1.model.User;
import security1.security1.repository.UserRepository;

@Service("principalOauth2UserService")
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    private final CustomBCryptPasswordEncoder bCryptPasswordEncoder;
    private final UserRepository userRepository;

    @Autowired
    public PrincipalOauth2UserService(CustomBCryptPasswordEncoder bCryptPasswordEncoder, UserRepository userRepository) {
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
        this.userRepository = userRepository;
    }


    // 구글로 부터 받은 userRequest 데이터에 대한 후처리가되는 함수
    // 함수 종료시 @AuthenticationPrincipal 어노테이션이 만들어진다.
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        System.out.println("userRequest : " + userRequest.getClientRegistration()); // registrationId로 어떤 OAuth로 로그인 했는지 확인가능
        System.out.println("userRequest : " + userRequest.getAccessToken().getTokenValue());

        // userRequest : {sub=111653458897920661963 <- Primary key 같은거, name=희성신, given_name=신, family_name=희성, picture=https://lh3.googleusercontent.com/a/ACg8ocKU98UCX9K3GETfjXL-eWH_dMopBcNkQySpuYAVfPszLg=s96-c, email=s23012@gsm.hs.kr, email_verified=true, locale=ko, hd=gsm.hs.kr}
        // username = "google_111653458897920661963"
        // password = "암호화 (겟인데어)" <- 이걸로 로그인 할거기 때문에 null만 아니고 아무거나 가능
        // email = "s23012@gsm.hs.kr"
        // role = "ROLE_USER"
        // provider = "google"
        // providerId = "111653458897920661963"
        // 이 정보로 회원가입 하면됨

        OAuth2User oAuth2User = super.loadUser(userRequest);

        // 구글 로그인 버튼 클릭 -> 구글 로그인 창 -> 로그인 완료 -> code를 리턴(OAuth-Client라이브러리) -> Access Token요청
        // userRequest 정보 -> loadUser 메서드 호출 -> 구글로부터 회원프로필을 받아와줌
        System.out.println("getAttributes : " + super.loadUser(userRequest).getAttributes());

        String provider = userRequest.getClientRegistration().getClientId(); // 구글
        String providerId = oAuth2User.getAttribute("sub");
        String username = provider + "_" + providerId; // ex. google_123123
        String password = bCryptPasswordEncoder.encode("겟인데어");
        String email = oAuth2User.getAttribute("email");
        String role = "ROLE_USER";

        User userEntity = userRepository.findByUsername(username);

        if (userEntity == null) {
            System.out.println("해당 계정으로 구글 로그인을 최초로 시도했습니다.");
            userEntity = User.builder()
                    .username(username)
                    .password(password)
                    .email(email)
                    .role(role)
                    .provider(provider)
                    .providerId(providerId)
                    .build();
            userRepository.save(userEntity);
        } else {
            System.out.println("해당 계정으로 구글 로그인을 한적이 있음");
        }

        return new PrincipalDetails(userEntity, oAuth2User.getAttributes());
    }
}
