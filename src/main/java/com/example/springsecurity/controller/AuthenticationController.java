package com.example.springsecurity.controller;

import com.example.springsecurity.config.JwtUtils;
import com.example.springsecurity.dao.UserDao;
import com.example.springsecurity.dto.AuthenticationRequest;

import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")

public class AuthenticationController {
     private final AuthenticationManager authenticationManager;
     private final UserDao userDao;
     private final JwtUtils jwtUtils;

    public AuthenticationController(AuthenticationManager authenticationManager, UserDao userDao, JwtUtils jwtUtils) {
        this.authenticationManager = authenticationManager;
        this.userDao = userDao;
        this.jwtUtils = jwtUtils;
    }


    @PostMapping("/authenticate")
    public ResponseEntity<String> authenticate(
        @RequestBody AuthenticationRequest request){
          authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getEmail(),request.getPassword()));
          final UserDetails user = userDao.findUserByEmail(request.getEmail());
          if(user!=null){
             return ResponseEntity.ok(jwtUtils.generateToken(user));
          }
          return ResponseEntity.status(400).body("Some error has occured");
    }
}
