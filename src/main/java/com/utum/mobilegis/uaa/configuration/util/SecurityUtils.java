package com.utum.mobilegis.uaa.configuration.util;


import com.utum.mobilegis.domain.GisUser;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;


/**
 * 根据请求头携带的access_token获取请求令牌中的用户信息
 */
@Component
public class SecurityUtils {


    /**
     * 获取用户令牌中的个人信息
     *
     * @return UserDetail 返回类型
     * @Title: getPrincipal
     */
    public static GisUser getPrincipal() {
        Object o = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (o instanceof GisUser)
            return (GisUser) o;
        return null;
    }

    /**
     * 获取当前用户id
     */
    public static long getUserId() {
        GisUser user = getPrincipal();
        if (null == user)
            return -1;
        return user.getId();
    }

    public static String getUsername() {
        GisUser user = getPrincipal();
        if (null == user)
            return "-1";
        return user.getUsername();
    }


    /**
     * 判断是否为管理员
     */
    public static boolean isAdmin() {
        GisUser user = getPrincipal();
        if (null == user)
            return false;
        if (user.getUsername().equals("admin"))
            return true;
        return false;
    }


}