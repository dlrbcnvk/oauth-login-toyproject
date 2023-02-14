package com.tutorial.jsg.oauth.service;

import com.tutorial.jsg.api.entity.User;
import com.tutorial.jsg.api.repository.UserRepository;
import com.tutorial.jsg.oauth.entity.UserPrincipal;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    /**
     * TODO
     * UserDetailsService 구조 확인할 것
     * 이렇게 간단한 처리만으로 끝이라고...?
     */
    @Override
    public UserDetails loadUserByUsername(String userId) throws UsernameNotFoundException {
        User user = userRepository.findByUserId(userId);
        if (user == null) {
            throw new UsernameNotFoundException("Cannot find username.");
        }
        return UserPrincipal.create(user);
    }
}
