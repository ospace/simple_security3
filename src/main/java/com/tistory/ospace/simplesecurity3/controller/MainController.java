package com.tistory.ospace.simplesecurity3.controller;

//import java.util.Arrays;

import javax.servlet.http.HttpServletRequest;

//import org.springframework.security.core.Authentication;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
//import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RequestMapping;
//import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class MainController {
	private static Logger LOGGER = LoggerFactory.getLogger(MainController.class);
	
	@ExceptionHandler({Exception.class})
	public void handleException(HttpServletRequest request, Exception ex) {
		LOGGER.error("{}[{}]", ex.getClass().getName(), ex.getMessage(), ex);
	}
	
	@RequestMapping("/")
	public String index(HttpServletRequest req) {
		LOGGER.info("index begin");
		return "redirect:/main.html";
	}

}
