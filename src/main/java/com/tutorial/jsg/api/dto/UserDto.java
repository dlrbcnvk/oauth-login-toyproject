package com.tutorial.jsg.api.dto;

import com.tutorial.jsg.api.entity.User;

public class UserDto {

    private String userId;
    private String username;
    private String email;
    private String profileImageUrl;
    private String provider;
    private String role;
    private String refreshToken;

    public UserDto(User user) {
        this.userId = user.getUserId();
        this.username = user.getUsername();
        this.email = user.getEmail();
        this.profileImageUrl = user.getProfileImageUrl();
        this.provider = user.getProviderType().toString();
        this.role = user.getRoleType().toString();
        this.refreshToken = user.getUserRefreshToken().getRefreshToken();
    }
}
