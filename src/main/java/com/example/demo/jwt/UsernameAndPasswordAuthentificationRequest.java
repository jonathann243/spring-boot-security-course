package com.example.demo.jwt;

public class UsernameAndPasswordAuthentificationRequest {
    private String username;
    private String password;

    public UsernameAndPasswordAuthentificationRequest() {
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
