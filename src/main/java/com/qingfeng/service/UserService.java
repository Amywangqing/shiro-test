package com.qingfeng.service;

import com.qingfeng.model.User;

public interface UserService {

    User findByUsername(String username);
}
