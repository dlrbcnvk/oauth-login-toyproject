package com.tutorial.jsg.oauth.userinfo;

import com.tutorial.jsg.oauth.entity.ProviderType;
import com.tutorial.jsg.oauth.userinfo.impl.FacebookUserInfo;
import com.tutorial.jsg.oauth.userinfo.impl.GoogleUserInfo;

import java.util.Map;

public class OAuth2UserInfoFactory {
    public static OAuth2UserInfo getOAuth2UserInfo(ProviderType providerType, Map<String, Object> attributes) {
        switch (providerType) {
            case GOOGLE: return new GoogleUserInfo(attributes);
            case FACEBOOK: return new FacebookUserInfo(attributes);
            case NAVER: return new FacebookUserInfo(attributes);
            case KAKAO: return new FacebookUserInfo(attributes);
            case GITHUB: return new FacebookUserInfo(attributes);
            default: throw new IllegalArgumentException("Invalid Provider Type.");
        }
    }
}
