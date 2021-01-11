package com.tistory.ospace.simplesecurity3.configuration;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.rememberme.TokenBasedRememberMeServices;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.tistory.ospace.simplesecurity3.entity.Response;

@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    private static final Logger LOGGER = LoggerFactory.getLogger(WebSecurityConfig.class);
    
	private static MappingJackson2HttpMessageConverter jsonConverter = new MappingJackson2HttpMessageConverter(
	        new ObjectMapper()
	            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
	            .registerModule(new JavaTimeModule())
	    );
	
	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
		auth.inMemoryAuthentication()
			.withUser("admin").password(passwordEncoder().encode("adminpass")).roles("ADMIN")
			.and()
			.passwordEncoder(passwordEncoder())
		;
	}
	
	@Override
	public void configure(WebSecurity web) throws Exception {
		web.ignoring().antMatchers("/assets/**", "/js/**");
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.headers().frameOptions().disable()
		    .and().csrf().disable()
		    .authorizeRequests()
		    	.antMatchers("/login**", "/thankyou**").permitAll()
				.anyRequest().authenticated()
				.and()
			.formLogin()
				//.loginPage("/login.html") // 인증페이지 경로
				.loginProcessingUrl("/login")
				.successHandler(loginSuccessHandler())
                .failureHandler(loginFailureHandler())
				.and()
			.logout()
				.logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
				.logoutSuccessHandler(logoutSuccessHandler())
				.deleteCookies("JSESSIONID")
				.deleteCookies("REMEMBER_ME_COOKIE")
				.invalidateHttpSession(true)
				.and()
			.rememberMe()
				.key("REMEMBER_ME_KEY")
				.rememberMeServices(tokenBasedRememberMeServices())
				.and()
			.exceptionHandling()
			    .authenticationEntryPoint(authenticationEntryPoint())
			    
			;
	}
	
	@Bean
	public RememberMeServices tokenBasedRememberMeServices() {
		TokenBasedRememberMeServices tokenBasedRememberMeServices = new TokenBasedRememberMeServices("REMEBMER_ME_KEY", userDetailsService());
		//tokenBasedRememberMeServices.setAlwaysRemember(true);								// 체크박스 클릭안해도 무조건 유지
		tokenBasedRememberMeServices.setTokenValiditySeconds( 60*60*24*30 ); //30일(60초*60분*24시*30일)
		tokenBasedRememberMeServices.setCookieName("REMEMBER_ME_COOKIE");
		return tokenBasedRememberMeServices;
	}
	
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	
	private AuthenticationSuccessHandler loginSuccessHandler() {
        return new SavedRequestAwareAuthenticationSuccessHandler() {
            @Override
            public void onAuthenticationSuccess(HttpServletRequest req, HttpServletResponse res, Authentication auth) throws IOException {
                String accept = req.getHeader("accept");
                
                LOGGER.info("onAuthenticationSuccess begin: accept[{}]", accept);
                
                res.setStatus(HttpServletResponse.SC_OK);
            }
        };
    }
    
    private AuthenticationFailureHandler loginFailureHandler() {
        return new SimpleUrlAuthenticationFailureHandler() {
            @Override
            public void onAuthenticationFailure(HttpServletRequest req, HttpServletResponse res, AuthenticationException ex) throws IOException {
                LOGGER.info("onAuthenticationFailure begin:");
                
                writeJson(HttpServletResponse.SC_UNAUTHORIZED, "AuthorizeFailed", ex.getMessage(), req, res);
                LOGGER.error("onAuthenticationFailure end:");
            }
        };
    }
    
    private LogoutSuccessHandler logoutSuccessHandler() {
        return new LogoutSuccessHandler() {
            @Override
            public void onLogoutSuccess(HttpServletRequest req, HttpServletResponse res, Authentication auth)
                    throws IOException, ServletException {
                LOGGER.info("onLogoutSuccess begin:");
                
                if (null == auth) {
                    writeJson(HttpServletResponse.SC_BAD_REQUEST, "BadRequest", "no authentication", req, res);
                } else {
                    // 인증된 상태
                }
            }
        };
    }
    
    private AuthenticationEntryPoint authenticationEntryPoint() {
        return new AuthenticationEntryPoint() {
            @Override
            public void commence(HttpServletRequest req, HttpServletResponse res, AuthenticationException authEx)
                    throws IOException, ServletException {
                LOGGER.error("authenticationEntryPoint begin: authEx[{}]", authEx.getMessage());
                res.sendError(HttpServletResponse.SC_UNAUTHORIZED, authEx.getMessage());
                //미인증된 사용자는 login 페이지로 이동할 수 있음.
                //res.sendRedirect("/login.html");
            }
        };
    }
    
    private static void writeJson(int status, String error, String message, HttpServletRequest req, HttpServletResponse res) throws HttpMessageNotWritableException, IOException {
        res.setStatus(status);
        jsonConverter.write(Response.of(status, error, message, req.getRequestURI()), MediaType.APPLICATION_JSON, new ServletServerHttpResponse(res));
    }
}
