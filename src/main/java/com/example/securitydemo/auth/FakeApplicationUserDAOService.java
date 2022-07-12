package com.example.securitydemo.auth;

import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import static com.example.securitydemo.security.ApplicationUserRole.ADMIN;
import static com.example.securitydemo.security.ApplicationUserRole.ADMIN_TRAINEE;
import static com.example.securitydemo.security.ApplicationUserRole.STUDENT;

@Repository("fake")
public class FakeApplicationUserDAOService implements ApplicationUserDAO {

    private final PasswordEncoder passwordEncoder;

    public FakeApplicationUserDAOService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Optional<AplicationUser> selectApplicationUserByUsername(String userName) {
        return getAplicationUsers().stream()
                .filter(e -> e.getUsername().equals(userName))
                .findFirst();
    }

    private Set<AplicationUser> getAplicationUsers() {
        Set<AplicationUser> users = Sets.newHashSet(

                new AplicationUser(
                        STUDENT.getGrantedAuthorities(),
                        passwordEncoder.encode("password"),
                        "annasmith",
                        true,
                        true,
                        true,
                        true
                ),
                new AplicationUser(
                        ADMIN.getGrantedAuthorities(),
                        passwordEncoder.encode("admin"),
                        "admin",
                        true,
                        true,
                        true,
                        true
                ),
                new AplicationUser(
                        ADMIN_TRAINEE.getGrantedAuthorities(),
                        passwordEncoder.encode("tom"),
                        "tom",
                        true,
                        true,
                        true,
                        true
                )
        );
        return users;
    }
}
