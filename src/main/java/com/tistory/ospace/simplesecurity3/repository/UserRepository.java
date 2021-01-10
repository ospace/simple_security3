package com.tistory.ospace.simplesecurity3.repository;

import java.util.Collection;
import java.util.List;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import com.tistory.ospace.simplesecurity3.entity.User;


@Mapper
public interface UserRepository {
	
	Integer countBy(@Param("entity") User entity);
	
	List<User> findAllBy(@Param("entity") User entity);
	
	List<User> findAllIn(@Param("ids") Collection<Integer> ids);
	
	User findById(String id);
	
	User findBy(User entity);
	
	void insert(User entity);
	
	void update(User entity);
	
	void deleteById(String id);
}
