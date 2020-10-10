package com.qingfeng.mapper;


import org.apache.ibatis.annotations.Param;

import com.qingfeng.model.User;

public interface UserMapper {

    User findByUsername(@Param("username") String username);
}
