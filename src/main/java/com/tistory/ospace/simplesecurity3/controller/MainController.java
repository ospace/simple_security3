package com.tistory.ospace.simplesecurity3.controller;

import java.util.Arrays;

//import java.util.Arrays;

import javax.servlet.http.HttpServletRequest;

//import org.springframework.security.core.Authentication;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.ExceptionHandler;
//import org.springframework.web.bind.annotation.PathVariable;
//import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
//import org.springframework.web.bind.annotation.RequestParam;

import com.tistory.ospace.simplesecurity3.entity.Authority;
import com.tistory.ospace.simplesecurity3.entity.User;
import com.tistory.ospace.simplesecurity3.service.UserService;

@Controller
//@RequestMapping("/")
public class MainController {
	private static Logger logger = LoggerFactory.getLogger(MainController.class);
	
	@Autowired
	private UserService userService;
	
	@ExceptionHandler({Exception.class})
	public void handleException(HttpServletRequest request, Exception ex) {
		logger.error("{}[{}]", ex.getClass().getName(), ex.getMessage(), ex);
	}
	
	@PostMapping("/register")
	public String register(User user) {
		logger.info("register begin: user[{}]", user);
		
		if(StringUtils.isEmpty(user.getUsername()) || StringUtils.isEmpty(user.getPassword())) {
			throw new RuntimeException("invalid parameters");
		}
		
		user.setAuthorities(Arrays.asList(Authority.of("USER")));
		user.setEnabled(true);
		
		userService.save(user);
		
		logger.info("register end");
		
		return "redirect:/";
	}
	
	@RequestMapping("/")
	public String index(HttpServletRequest req) {
		return "redirect:/main";
	}
	
	@RequestMapping("/main")
	public String main(HttpServletRequest req) {
		return "main";
	}
	
	@RequestMapping("/login")
	public String loginForm(HttpServletRequest req) {
		String referer = req.getHeader("Referer");
		logger.info("login begin: Referer[{}]", referer);
		
		req.getSession().setAttribute("prevPage", referer);
		
		logger.info("login end:");
		return "login";
	}
}
