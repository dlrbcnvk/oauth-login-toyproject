package com.tutorial.jsg.oauth.userinfo.impl;

import com.tutorial.jsg.oauth.userinfo.OAuth2UserInfo;

import java.util.Map;

public class GithubUserInfo extends OAuth2UserInfo {

    public GithubUserInfo(Map<String, Object> attributes) {
        super(attributes);
    }

    @Override
    public String getId() {
        return (String) attributes.get("id");
    }

    @Override
    public String getName() {
        return (String) attributes.get("name");
    }

    @Override
    public String getEmail() {
        return (String) attributes.get("email");
    }

    @Override
    public String getImageUrl() {
        return (String) attributes.get("avatar_url");
    }
}
