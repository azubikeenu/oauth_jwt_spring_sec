package com.azubike.ellipsis.springsecuritywithjwt.controller;

import com.azubike.ellipsis.springsecuritywithjwt.model.LoginRequest;
import com.azubike.ellipsis.springsecuritywithjwt.service.TokenService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthController {
    private final Logger logger = LoggerFactory.getLogger(AuthController.class);
    private final TokenService tokenService;

    private final AuthenticationManager authenticationManager;

    public AuthController(final TokenService tokenService, final AuthenticationManager authenticationManager) {
        this.tokenService = tokenService;
        this.authenticationManager = authenticationManager;
    }

//    @Deprecated
//    @PostMapping("/token")
//    public String token(Authentication authentication) {
//        logger.debug("Requesting authentication for {}", authentication.getName());
//        String token = tokenService.generateToken(authentication);
//        logger.debug("Token granted : {}", token);
//        return token;
//    }


    @PostMapping("/token")
    public String authenticate(@RequestBody LoginRequest request){
        System.out.printf("username :  %s password : %s\n" ,request.username() , request.password());
        final Authentication authenticate = authenticationManager.
                authenticate(new UsernamePasswordAuthenticationToken(request.username(), request.password()));
         return tokenService.generateToken(authenticate);
    }


}
