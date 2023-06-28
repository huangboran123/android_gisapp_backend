package com.utum.mobilegis.uaa.configuration;

import com.alibaba.fastjson.JSONObject;
import com.utum.mobilegis.domain.GisUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.authentication.TokenExtractor;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.stereotype.Component;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * @创建时间 : 2023/6/27
 * @作者 : huangboran
 * @类描述 :
 **/
public class UserPackagFilter extends BasicAuthenticationFilter {

    @Autowired
    private TokenStore tokenStore;

    public UserPackagFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {

        // 过滤器中验证access_token
        String access_token = request.getHeader("Authorization");
        if (access_token != null && access_token.startsWith("Bearer ")) {
            access_token = access_token.substring(7);
        }
       if(access_token != null){
                Object principal= null;
                Authentication authentication = tokenStore.readAuthentication(access_token);
           if (authentication != null) {
                    principal = authentication.getPrincipal();
                }
           GisUser user = new GisUser();
           user.setUsername(principal.toString());
           UsernamePasswordAuthenticationToken authenticationToken
                        = new UsernamePasswordAuthenticationToken(user, null, new ArrayList<>());
           SecurityContextHolder.getContext().setAuthentication(authenticationToken);
       }
        chain.doFilter(request, response);
    }

}