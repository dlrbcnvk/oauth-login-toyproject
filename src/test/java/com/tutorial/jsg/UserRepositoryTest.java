package com.tutorial.jsg;

import com.tutorial.jsg.api.entity.User;
import com.tutorial.jsg.api.entity.UserRefreshToken;
import com.tutorial.jsg.api.repository.UserRefreshTokenRepository;
import com.tutorial.jsg.api.repository.UserRepository;
import com.tutorial.jsg.oauth.entity.ProviderType;
import com.tutorial.jsg.oauth.entity.RoleType;
import org.assertj.core.api.Assertions;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.Rollback;

import java.time.LocalDateTime;
import java.util.NoSuchElementException;

import static org.assertj.core.api.Assertions.*;

@SpringBootTest
public class UserRepositoryTest {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private UserRefreshTokenRepository userRefreshTokenRepository;

    @Test
    @Rollback
    void userAdd() {
        LocalDateTime now = LocalDateTime.now();
        User user = new User("111", "user1", "user@aaa.com", "y", "yy", ProviderType.LOCAL, RoleType.USER, now, now);
        userRepository.save(user);

        User findUser = userRepository.findByUserId("111");

        assertThat(user.getUserId()).isEqualTo(findUser.getUserId());
    }

    @Test
    @Rollback
    void userIdUnique() {
        LocalDateTime now = LocalDateTime.now();
        User user1 = new User("111", "user1", "user@aaa.com", "y", "yy", ProviderType.LOCAL, RoleType.USER, now, now);
        User user2 = new User("111", "user2", "user@bbb.com", "y", "yy", ProviderType.LOCAL, RoleType.USER, now, now);
        userRepository.save(user1);
        userRepository.save(user2);

        // unique 조건에 위배되어 나오는 exception은 뭘까...?
        Assertions.assertThatThrownBy(() -> {
            userRepository.save(user1);
            userRepository.save(user2);
        }).isInstanceOf(NoSuchElementException.class);
    }

    @Test
    @Rollback
    void userAndToken() {
        LocalDateTime now = LocalDateTime.now();
        User user1 = new User("111", "user1", "user@aaa.com", "y", "yy", ProviderType.LOCAL, RoleType.USER, now, now);
        UserRefreshToken userRefreshToken = new UserRefreshToken(user1.getUserId(), "dsafknjkeaf");

        userRepository.saveAndFlush(user1);
        userRefreshTokenRepository.saveAndFlush(userRefreshToken);

        UserRefreshToken findToken = userRefreshTokenRepository.findByUserId(user1.getUserId());

        Assertions.assertThat(findToken.getRefreshToken()).isEqualTo(userRefreshToken.getRefreshToken());
    }

}
