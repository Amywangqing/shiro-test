package com.qingfeng.service.impl;

import javax.annotation.Resource;

import org.springframework.stereotype.Service;

import com.qingfeng.mapper.UserMapper;
import com.qingfeng.model.User;
import com.qingfeng.service.UserService;

@Service
public class UserServiceImpl implements UserService {

    @Resource
    private UserMapper userMapper;

    @Override
    public User findByUsername(String username) {
        return userMapper.findByUsername(username);
    }
}
