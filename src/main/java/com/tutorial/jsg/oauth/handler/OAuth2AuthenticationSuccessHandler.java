package com.tutorial.jsg.oauth.handler;

import com.tutorial.jsg.api.entity.User;
import com.tutorial.jsg.api.entity.UserRefreshToken;
import com.tutorial.jsg.api.repository.UserRefreshTokenRepository;
import com.tutorial.jsg.api.repository.UserRepository;
import com.tutorial.jsg.config.properties.AppProperties;
import com.tutorial.jsg.oauth.entity.ProviderType;
import com.tutorial.jsg.oauth.entity.RoleType;
import com.tutorial.jsg.oauth.repository.OAuth2AuthorizationRequestBasedOnCookieRepository;
import com.tutorial.jsg.oauth.token.AuthToken;
import com.tutorial.jsg.oauth.token.AuthTokenProvider;
import com.tutorial.jsg.oauth.userinfo.OAuth2UserInfo;
import com.tutorial.jsg.oauth.userinfo.OAuth2UserInfoFactory;
import com.tutorial.jsg.utils.CookieUtil;
import com.tutorial.jsg.utils.OAuth2Util;
import com.tutorial.jsg.utils.TokenUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.Collection;
import java.util.Date;
import java.util.Optional;

import static com.tutorial.jsg.oauth.repository.OAuth2AuthorizationRequestBasedOnCookieRepository.REDIRECT_URI_PARAM_COOKIE_NAME;
import static com.tutorial.jsg.oauth.repository.OAuth2AuthorizationRequestBasedOnCookieRepository.REFRESH_TOKEN;

@Component
@RequiredArgsConstructor
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final AuthTokenProvider tokenProvider;
    private final UserRefreshTokenRepository userRefreshTokenRepository;
    private final OAuth2AuthorizationRequestBasedOnCookieRepository authorizationRequestRepository;


    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        String targetUrl = determineTargetUrl(request, response, authentication);

        if (response.isCommitted()) {
            logger.debug("Response has already been committed. Unable to redirect to " + targetUrl);
            return;
        }

        clearAuthenticationAttributes(request, response);
        getRedirectStrategy().sendRedirect(request, response, targetUrl);

    }

    private void clearAuthenticationAttributes(HttpServletRequest request, HttpServletResponse response) {
        super.clearAuthenticationAttributes(request);
        authorizationRequestRepository.removeAuthorizationRequestCookies(request, response);

    }

    @Override
    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        Optional<String> redirectUri = CookieUtil.getCookie(request, REDIRECT_URI_PARAM_COOKIE_NAME)
                .map(Cookie::getValue);

        if (redirectUri.isPresent() && !isAuthorizedRedirectUri(redirectUri.get())) {
            throw new IllegalArgumentException("Unauthorized Redirect URI...cannot proceed with the authentication");
        }

        String targetUrl = redirectUri.orElse(getDefaultTargetUrl());

        OAuth2AuthenticationToken authToken = (OAuth2AuthenticationToken) authentication;
        ProviderType providerType = ProviderType.valueOf(authToken.getAuthorizedClientRegistrationId().toUpperCase());

        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        OAuth2UserInfo userInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(providerType, oAuth2User.getAttributes());
        Collection<? extends GrantedAuthority> authorities = ((OAuth2User) authentication.getPrincipal()).getAuthorities();

        RoleType roleType = hasAuthority(authorities, RoleType.ADMIN.getCode()) ? RoleType.ADMIN : RoleType.USER;

        Date now = new Date();
        AuthToken accessToken = tokenProvider.createAuthToken(
                userInfo.getId(),
                roleType.getCode(),
                new Date(now.getTime() + TokenUtil.TOKEN_EXPIRY)
        );

        // refresh token 설정
        long refreshTokenExpiry = TokenUtil.REFRESH_TOKEN_EXPIRY;

        AuthToken refreshToken = tokenProvider.createAuthToken(
                "refresh_token",
                new Date(now.getTime() + refreshTokenExpiry)
        );

        // DB 저장
        UserRefreshToken userRefreshToken = userRefreshTokenRepository.findByUserId(userInfo.getId());
        if (userRefreshToken != null) {
            userRefreshToken.setRefreshToken(refreshToken.getToken());
        } else {
            /**
             실시간 처리인데, User 엔티티와 UserRefreshToken 간에 연관관계를 맺는 것이 적절한지 의문.
             데이터 정합성을 생각해서 연관관계를 매핑했는데,
             실시간 처리라는 점을 생각하면 정합성 포기하는 대신 쿼리 한번 줄이는 게 더 적절하지 않을까 싶다
             그렇지만 refreshToken 기한이 만료될 때만 User 엔티티를 조회하므로 그렇게 빈번하게 일어나지는 않을 것 같아서
             데이터 정합성을 위해 연관관계를 매핑하는 것이 좋다고 판단
             연관관계가 필요한가...
             연관관계를 맺는다는 건 하나의 데이터베이스(스키마) 내에서 연관을 맺는다는 것.
             User 테이블이 앞으로 쓰일 곳이 많을 것이고, 데이터베이스의 커넥션 풀은 한정되어있는데,
             사용자가 새로운 url 요청할 때마다 jwt 토큰 주고받느라, 그 사이에서 RefreshToken을 db에 저장했다가 조회했다가 그러느라
             커넥션을 과도하게 사용...
             커넥션이 문제라면 연관관계를 맺지 않아도 커넥션은 동일하게 많이 사용됨
             게다가 커넥션 사용은 네트워크 비용이 큼
             -> 사용자와 주고받는 JWT는 RDB가 아니라 redis에 보관하고 꺼내 쓰는게 좋지 않을까..

             -- redis --
             redis 호출하는 컨트롤러를 만들고, 필요한 곳에서 restTemplate으로 redis api 요청하여 데이터 넣고 빼고 조회하기...?
             UserRefreshToken은 어쩌지...jpa랑은 관련없는 거 같은데..?
            */

            userRefreshToken = new UserRefreshToken(userInfo.getId(), refreshToken.getToken());
            userRefreshTokenRepository.saveAndFlush(userRefreshToken);
        }

        int cookieMaxAge = (int) refreshTokenExpiry / 60;

        CookieUtil.deleteCookie(request, response, REFRESH_TOKEN);
        CookieUtil.addCookie(response, REFRESH_TOKEN, refreshToken.getToken(), cookieMaxAge);

        return UriComponentsBuilder.fromUriString(targetUrl)
                .queryParam("token", accessToken.getToken())
                .build().toUriString();
    }

    private boolean isAuthorizedRedirectUri(String uri) {
        URI clientRedirectUri = URI.create(uri);
        URI authorizedUri = URI.create(OAuth2Util.AUTHORIZED_REDIRECT_URI);

        if (authorizedUri.getHost().equalsIgnoreCase(clientRedirectUri.getHost())
                && authorizedUri.getPort() == clientRedirectUri.getPort()) {
            return true;
        }
        return false;
    }

    private boolean hasAuthority(Collection<? extends GrantedAuthority> authorities, String authority) {
        if (authorities == null) {
            return false;
        }

        for (GrantedAuthority grantedAuthority : authorities) {
            if (authority.equals(grantedAuthority.getAuthority())) {
                return true;
            }
        }
        return false;
    }






}
