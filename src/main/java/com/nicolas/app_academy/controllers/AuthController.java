package com.nicolas.app_academy.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.nicolas.app_academy.dto.Login;
import com.nicolas.app_academy.dto.Register;
import com.nicolas.app_academy.services.ILoginService;

@RestController
@RequestMapping("/auth")
@CrossOrigin({ "*" })
public class AuthController {

  @Autowired
  private ILoginService<String> loginService;

  @PostMapping("/login")
  public ResponseEntity<String> logar(@RequestBody Login login) {
    return loginService.login(login);
  }

  @PostMapping("/register")
  public ResponseEntity<String> register(@RequestBody Register register) {
    return loginService.register(register);
  }
}
