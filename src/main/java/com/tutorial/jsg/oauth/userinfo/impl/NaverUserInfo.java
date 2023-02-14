package com.tutorial.jsg.oauth.userinfo.impl;

import com.tutorial.jsg.oauth.userinfo.OAuth2UserInfo;

import java.util.Map;

public class NaverUserInfo extends OAuth2UserInfo {

    private Map<String, Object> response;

    public NaverUserInfo(Map<String, Object> attributes) {
        super(attributes);
        this.response = (Map<String, Object>) attributes.get("response");
    }

    @Override
    public String getId() {

        if (response == null) {
            return null;
        }

        return (String) attributes.get("id");
    }

    @Override
    public String getName() {

        if (response == null) {
            return null;
        }

        return (String) attributes.get("name");
    }

    @Override
    public String getEmail() {

        if (response == null) {
            return null;
        }

        return (String) attributes.get("email");
    }

    @Override
    public String getImageUrl() {

        if (response == null) {
            return null;
        }

        return (String) attributes.get("profile_image");
    }
}
