package com.online_exam.examer;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import org.springframework.scheduling.annotation.EnableScheduling;

//@EnableCaching
@EnableAspectJAutoProxy
@SpringBootApplication
@EnableScheduling
public class ExamerApplication {public static void main(String[] args) {SpringApplication.run(ExamerApplication.class, args);}}
