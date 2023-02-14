package com.tutorial.jsg.api.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.sun.istack.NotNull;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "USER_REFRESH_TOKEN")
public class UserRefreshToken {
    @JsonIgnore
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long refreshTokenSeq;

    @OneToOne
    @JoinColumn(name = "USER_ID", unique = true)
    @NotNull
    private User user;

    @Column(name = "REFRESH_TOKEN", length = 256)
    @NotNull
    private String refreshToken;

    public UserRefreshToken(
        @NotNull User user,
        @NotNull String refreshToken
    ) {
        this.user = user;
        this.refreshToken = refreshToken;
    }
}
