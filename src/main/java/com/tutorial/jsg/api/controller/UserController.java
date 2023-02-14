package com.tutorial.jsg.api.controller;

import com.tutorial.jsg.api.dto.UserDto;
import com.tutorial.jsg.api.entity.User;
import com.tutorial.jsg.api.service.UserService;
import com.tutorial.jsg.oauth.entity.UserPrincipal;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @GetMapping("/api/v1/user")
    public UserDto getUser(@AuthenticationPrincipal UserPrincipal principal) {

        User user = userService.getUser(principal.getUserId());

        UserDto userDto = new UserDto(user);

        return userDto;
    }
}
