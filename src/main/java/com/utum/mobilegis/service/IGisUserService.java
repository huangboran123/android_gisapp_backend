package com.utum.mobilegis.service;

import com.utum.mobilegis.domain.GisUser;

public interface IGisUserService {
    /**
     * 用户注册
     * @param gisUser
     * @return
     */
    int register(GisUser gisUser);

    /**
     * 用户名是否存在
     * @param gisUser
     * @return
     */
    int isusernameAlreadyExists(GisUser gisUser);

    /**
     * 手机号码是否存在
     * @param gisUser
     * @return
     */
    int isphoneAlreadyExists(GisUser gisUser);

    /**
     * 邮箱是否存在
     * @param gisUser
     * @return int
     */
    int isemailAlreadyExists(GisUser gisUser);

    /**
     * 根据登录用户名获取用户信息（可以是手机号邮箱或用户名）
     * @param username
     * @return
     */
    GisUser getUserByUserName(String username);

    /**
     * 根据用户id获取用户信息
     * @param userId
     */
    GisUser getUserByUserId(long userId);
}
