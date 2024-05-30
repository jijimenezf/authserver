package com.demo.authserver;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.Map;

@RestController
public class AuthController {
    private static final Logger CONSOLE = LoggerFactory.getLogger(AuthController.class);

    private final TokenService tokenService;

    public AuthController(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    @PostMapping("/oauth2/token")
    public String token(Authentication authentication, @RequestParam Map<String,String> allParams) {
        CONSOLE.info("Authorities {}", authentication.getAuthorities());
        //allParams.forEach((Key, Value) -> CONSOLE.info("Key is {} and Value is {}", Key, Value));
        CONSOLE.info("Token requested for user: '{}' ", authentication.getName());
        String token = tokenService.generateToken(authentication);
        CONSOLE.info("Token granted: {} ", token);

        return token;
    }

    @GetMapping("/")
    public String home(Principal principal) {
        return "Hello " + principal.getName();
    }

    @GetMapping("/secure")
    public String secure() {
        return "This server is secure";
    }
}
