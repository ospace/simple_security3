package com.tistory.ospace.simplesecurity3;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.ApplicationPidFileWriter;

@SpringBootApplication
public class SimpleSecurity3Application {
	public static void main(String[] args) {
		SpringApplication springApplication = new SpringApplication(SimpleSecurity3Application.class);
		springApplication.addListeners(new ApplicationPidFileWriter("app.pid"));
		springApplication.run(args);
	}
}
