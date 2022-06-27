package com.jisu.securityproject.domain;

import lombok.Getter;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;

@Entity
@Getter
public class Account {

    @Id @GeneratedValue
    private Long id;
    private String username;
    private String password;
    private String email;
    private String age;
    private String role;

    protected Account() {}

    public Account(String username, String password, String email, String age, String role) {
        this.username = username;
        this.password = password;
        this.email = email;
        this.age = age;
        this.role = role;
    }

    public void encodPassword(String password) {
        this.password = password;
    }
}
