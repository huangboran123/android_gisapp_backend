package com.utum.mobilegis.uaa.service;

import com.utum.mobilegis.domain.GisUser;
import com.utum.mobilegis.service.IGisUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/**
 * @创建时间 : 2023/6/27
 * @作者 : huangboran
 * @类描述 : 用户服务类，用于加载用户信息
 **/
@Service
public class UserOAuthDetailsService implements UserDetailsService {


    @Autowired
    private IGisUserService iGisUserService;

    @Override
    public UserDetails loadUserByUsername(String username) {
        // 根据用户名从数据库或其他存储中加载用户信息
        GisUser gisuser= iGisUserService.getUserByUserName(username);

        if(gisuser == null) {
            return null;
        }
        List<GrantedAuthority> authorityList = new ArrayList<>();
        UserDetails userDetails = User.withUsername(gisuser.getUsername()).password(gisuser.getPassword()).authorities(authorityList).build();
        return userDetails;
    }
}

