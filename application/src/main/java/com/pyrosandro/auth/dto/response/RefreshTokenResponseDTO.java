package com.pyrosandro.auth.dto.response;


import lombok.Data;

@Data
public class RefreshTokenResponseDTO {
    private String accessToken;
    private String refreshToken;
    private String type = "Bearer";

    public RefreshTokenResponseDTO(String accessToken, String refreshToken) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
    }
}
