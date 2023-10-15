package com.pyrosandro.auth.model;

import lombok.*;

import javax.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "auth_refresh_tokens")
@Getter
@Setter
@NoArgsConstructor
@ToString
@EqualsAndHashCode
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @OneToOne
    @JoinColumn(name = "auth_user", referencedColumnName = "id")
    private AuthUser authUser;

    private String refreshToken;

    private LocalDateTime expirationDate;


}
