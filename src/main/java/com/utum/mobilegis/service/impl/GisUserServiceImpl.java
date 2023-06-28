package com.utum.mobilegis.service.impl;

import com.utum.mobilegis.domain.GisUser;
import com.utum.mobilegis.mapper.GisUserMapper;
import com.utum.mobilegis.service.IGisUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class GisUserServiceImpl implements IGisUserService {

    @Autowired
    private GisUserMapper gisUserMapper;

    /**
     * 用户注册
     * @param gisUser
     * @return
     */
    @Override
    public int register(GisUser gisUser) {
        return gisUserMapper.register(gisUser);
    }

    /**
     * 用户名是否存在
     * @param gisUser
     * @return
     */
    @Override
    public int isusernameAlreadyExists(GisUser gisUser) {
        return gisUserMapper.isusernameAlreadyExists(gisUser);
    }

    /**
     * 手机号码是否存在
     * @param gisUser
     * @return
     */
    @Override
    public int isphoneAlreadyExists(GisUser gisUser) {
        return gisUserMapper.isphoneAlreadyExists(gisUser);
    }


    /**
     * 邮箱是否存在
     * @param gisUser
     * @return
     */
    @Override
    public int isemailAlreadyExists(GisUser gisUser) {
        return gisUserMapper.isemailAlreadyExists(gisUser);
    }

    /**
     * 工具登录用户名获取用户信息（可以是手机号邮箱或用户名）
     * @param username
     * @return
     */
    @Override
    public GisUser getUserByUserName(String username) {
        return gisUserMapper.getUserByUserName(username);
    }

    /**
     * 根据用户id获取用户信息
     * @param userId
     */
    @Override
    public GisUser getUserByUserId(long userId) {
        return gisUserMapper.getUserByUserId(userId);
    }
}
