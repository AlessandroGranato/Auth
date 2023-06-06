package com.pyrosandro.auth.dto.response;

import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class AuthorizeResourceResponseDTO {
    private Long userId;
    private List<String> roles;
}
