package com.oauthstudy.api.service;

import com.oauthstudy.api.entity.user.User;
import com.oauthstudy.api.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;

    public User getUser(String userId){
        return userRepository.findByUserId(userId);
    }
}
