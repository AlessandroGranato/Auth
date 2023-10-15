package com.pyrosandro.auth.dto.request;

import lombok.Data;

import javax.validation.constraints.NotBlank;

@Data
public class RefreshTokenRequestDTO {
    @NotBlank
    private String refreshToken;
}
