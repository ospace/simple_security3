package com.tistory.ospace.simplesecurity3.service;

import java.util.Collection;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import com.tistory.ospace.simplesecurity3.entity.User;
import com.tistory.ospace.simplesecurity3.repository.UserRepository;


@Service
public class UserService {
	@Autowired
	private UserRepository accountRepo;
	
	@Autowired
	private PasswordEncoder passwordEncoder;
	
	/**
	 * 사용자 조회
	 * @param usrSrl
	 * @return
	 */
	public User getById(String id){
		return  accountRepo.findById(id);
	}
	
	/**
	 * 사용자 삭제
	 * @param user
	 */
	@Transactional
	public void delete(User account) {
		accountRepo.deleteById(account.getUsername());
	}

	public List<User> searchIn(Collection<Integer> ids) {
		return accountRepo.findAllIn(ids);
	}

	public void save(User account) {
		if(null != account.getPassword()) {
			account.setPassword(passwordEncoder.encode(account.getPassword()));
		}
		
		if(account.getUsername() != null) {
			accountRepo.update(account);
		} else {
			if(null != accountRepo.findById(account.getUsername())) {
				throw new RuntimeException("아이디중복["+account.getUsername()+"]");
			}
			
			accountRepo.insert(account);
		}
	}

	public void deleteById(String id) {
		if(null == id) return;
		try {
			accountRepo.deleteById(id);	
		} catch(DataIntegrityViolationException ex) {
			throw new RuntimeException("계정삭제: id["+id+"]", ex);
		}
	}

	public User getByLoginId(String loginId) {
		if(StringUtils.isEmpty(loginId)) return null;
		return accountRepo.findById(loginId);
	}
}

