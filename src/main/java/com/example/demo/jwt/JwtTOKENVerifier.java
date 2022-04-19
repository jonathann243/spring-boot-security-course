package com.example.demo.jwt;

import com.google.common.base.Strings;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.awt.*;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class JwtTOKENVerifier extends OncePerRequestFilter {


    @Override//<1>Verifier token
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {
       //*1.0 Recuperation TOKEN  identifier="Authorization"
        String authorizationHeader = httpServletRequest.getHeader("Authorization");

        //*1.1 check if token contains a string barer in begining an not null
        if (Strings.isNullOrEmpty(authorizationHeader)||!authorizationHeader.startsWith("Bearer")){
            return;
        }
        //*1.2 ecraze barer for have only datatoken (request = berer+data )
        String token =authorizationHeader.replace("Bearer","");

        //*1.3 try get token
        try {
            String key="securesecuresecuresecuresecuresecuresecuresecure";//secret key for hashing

           Jws<Claims> claimsJws= Jwts.parser() //recuperation gen
                    .setSigningKey(Keys.hmacShaKeyFor(key.getBytes()))
                    .parseClaimsJws(token);
           Claims body=claimsJws.getBody();//get body
           String username = body.getSubject();//get subjetc usename
            var authorities = (List<Map<String , String>>) body.get("authorities");// get authoriies of subjet

            //Maps the Authorities
            Set<SimpleGrantedAuthority> simpleGrantedAuthorities = authorities.stream()
                    .map(m -> new SimpleGrantedAuthority(m.get("authority")))
                    .collect(Collectors.toSet());
                //define athentification data
            Authentication authentication= new UsernamePasswordAuthenticationToken(
                    username,
                    null,
                    simpleGrantedAuthorities //need to extend simpleGrantedAuthorities
            );
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }catch (JwtException e){
            throw new IllegalStateException(String.format("Token %s cannot be Trust ", token));
        }
        // after verification send the response
        filterChain.doFilter(httpServletRequest,httpServletResponse);

    }
}


