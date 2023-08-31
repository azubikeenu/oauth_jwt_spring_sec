package com.azubike.ellipsis.springsecuritywithjwt.controller;


import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
public class HomeController {
    @GetMapping("/")
    String getHome(Principal principal) {
        return String.format("Hello %s, this is the home page" , principal.getName());
    }
}
