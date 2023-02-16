package com.tutorial.jsg.api.repository;

import com.tutorial.jsg.api.entity.User;
import com.tutorial.jsg.api.entity.UserRefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRefreshTokenRepository extends JpaRepository<UserRefreshToken, Long> {

    UserRefreshToken findByUserId(String userId);
}
