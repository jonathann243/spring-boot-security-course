package com.example.demo.jwt;

import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;

import javax.crypto.SecretKey;

public class JwtSecretKey {
    private final JwtConfig jwtConfig;

    @Autowired//injection de jwtconfig dans la classe
    public JwtSecretKey(JwtConfig jwtConfig) {
        this.jwtConfig = jwtConfig;
    }


    @Bean
    public SecretKey getSecretKey(){
      return Keys.hmacShaKeyFor(jwtConfig.getSecretKey().getBytes());
    }
}
