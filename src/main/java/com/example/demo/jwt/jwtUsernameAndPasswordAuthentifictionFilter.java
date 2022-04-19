package com.example.demo.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.LocalDate;
import java.util.Date;

public class jwtUsernameAndPasswordAuthentifictionFilter extends UsernamePasswordAuthenticationFilter {
    //job  of class is verified credential


    private final AuthenticationManager authenticationManager;
    //inject  JWt config  and secret keys  and using in bottom
    private final  JwtConfig jwtConfig;
    private final SecretKey SecretKey;

    public jwtUsernameAndPasswordAuthentifictionFilter(AuthenticationManager authenticationManager,
                                                       JwtConfig jwtConfig
                                                        , javax.crypto.SecretKey secretKey) {
        this.authenticationManager = authenticationManager;
        this.jwtConfig = jwtConfig;
        SecretKey = secretKey;
    }



    @Override//Ctrl+O <1> generate la classe en question methode essayant connexion
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        try {
                    //Creation requete *0.1
                  UsernameAndPasswordAuthentificationRequest  authentificationRequest =new ObjectMapper().
                          readValue(request.getInputStream(),UsernameAndPasswordAuthentificationRequest.class);

                  //*0.2 Initailisation Authentification user
                  Authentication authentication= new UsernamePasswordAuthenticationToken(
                      authentificationRequest.getUsername(),
                          authentificationRequest.getPassword());

                  //*0.3 manager  check if user exist and return
                  Authentication authenticate=authenticationManager.authenticate(authentication);
                  return authenticate;
          }catch (IOException e){
            throw new RuntimeException(e);
          }

    }

    @Override// <2>construction token
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {

        //2.2 Buil token
        String token = Jwts.builder()
                .setSubject(authResult.getName())
                 .claim("authorities",authResult.getAuthorities())
                  .setIssuedAt(new Date())
                   .setExpiration(java.sql.Date.valueOf(LocalDate.now().plusWeeks(2)))//define day of expiration
                   .signWith(SecretKey).compact();
        //ajout du Token a la reponse retourner
        response.addHeader(jwtConfig.getAuthorizationHeader(), jwtConfig.getTokenPrefix() +token);
    }
}
