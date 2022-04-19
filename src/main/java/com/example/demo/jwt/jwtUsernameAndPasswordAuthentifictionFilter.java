package com.example.demo.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class jwtUsernameAndPasswordAuthentifictionFilter extends UsernamePasswordAuthenticationFilter {
    //job is verified credential
    private final AuthenticationManager authenticationManager;

    public jwtUsernameAndPasswordAuthentifictionFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override//Ctrl+O generate la classe en question methode essayant connexion
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        //
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
}
