package com.example.chatApp.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.chatApp.entities.User;
import com.example.chatApp.repositories.UserRepository;
import com.example.chatApp.security.JwtUtil;
import com.example.chatApp.services.UserService;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

	@Autowired
	private AuthenticationManager authManager;
	
	@Autowired
	private UserRepository userRepo;
	
	@Autowired
	private JwtUtil jwtUtil;
	
	@Autowired
	private PasswordEncoder passwordEncoder;
	
	@Autowired
	private UserService userService;
	
	
	@PostMapping("/signup")
	public String signUp(@RequestBody User user) {
		user.setPassword(passwordEncoder.encode(user.getPassword()));
		userRepo.save(user);
		return "User registered successfully";
	}
	
	@PostMapping("/login")
	public String logIn(@RequestBody User loginReq) {
		authManager.authenticate(new UsernamePasswordAuthenticationToken(loginReq.getUsername(), loginReq.getPassword()));
		UserDetails userDetails = userService.loadUserByUsername(loginReq.getUsername());
		return jwtUtil.generateToken(userDetails);
	}
}
