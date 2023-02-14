package com.tutorial.jsg.oauth.entity;

import lombok.Getter;
import lombok.ToString;

@Getter
@ToString
public enum ProviderType {
    NAVER,
    KAKAO,
    GOOGLE,
    FACEBOOK,
    GITHUB,
    LOCAL;
}
