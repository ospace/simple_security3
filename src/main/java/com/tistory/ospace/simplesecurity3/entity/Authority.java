package com.tistory.ospace.simplesecurity3.entity;

import org.apache.ibatis.type.Alias;
import org.springframework.security.core.GrantedAuthority;

@Alias("Authority")
public class Authority implements GrantedAuthority {
    private static final long serialVersionUID = 2970833796443419422L;
    
    private String username;
    private String authority;
    
    public static Authority of(String authority) {
    	Authority ret = new Authority();
    	ret.setAuthority(authority);
    	return ret;
    }
    public String getUsername() {
		return username;
	}
	public void setUsername(String username) {
		this.username = username;
	}
	public String getAuthority() {
        return authority;
    }
    public void setAuthority(String authority) {
        this.authority = authority;
    }
    
    public String toString() {
		return "username["+username+"] authority["+authority+"]";
	}
}
