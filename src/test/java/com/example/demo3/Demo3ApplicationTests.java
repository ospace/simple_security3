package com.example.demo3;

import org.junit.Test;
//import org.junit.jupiter.params.ParameterizedTest;
//import org.junit.jupiter.params.provider.CsvSource;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

@RunWith(SpringRunner.class)
@SpringBootTest
public class Demo3ApplicationTests {

//	@ParameterizedTest
//	@CsvSource(
//		{
//			"foo, 1",
//			"bar, 2"
//			
//		})
	@Test
	public void testCsvSource(String arg1, int arg2) {
		System.out.println(arg1 +", " + arg2);
	}
	
	
	@Test
	public void contextLoads() {
	}

}
