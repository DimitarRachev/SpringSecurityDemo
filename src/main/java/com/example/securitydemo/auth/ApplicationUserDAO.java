package com.example.securitydemo.auth;

import java.util.Optional;

public interface ApplicationUserDAO {

 Optional<AplicationUser> selectApplicationUserByUsername(String userName);
}
