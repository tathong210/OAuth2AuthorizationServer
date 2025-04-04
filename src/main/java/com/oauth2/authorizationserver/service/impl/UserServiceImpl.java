package com.oauth2.authorizationserver.service.impl;

import com.oauth2.authorizationserver.repository.UserRepository;
import com.oauth2.authorizationserver.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {
    private final UserRepository userRepository;
}
