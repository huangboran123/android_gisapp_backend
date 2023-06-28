package com.utum.mobilegis.controller;

import com.utum.mobilegis.domain.GisUser;
import com.utum.mobilegis.domain.Results;
import com.utum.mobilegis.service.IGisUserService;
import com.utum.mobilegis.uaa.configuration.util.SecurityUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.endpoint.TokenEndpoint;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static com.utum.mobilegis.Utills.Constants.*;


@RestController
@RequestMapping("/user")
public class GisUserController {
    @Autowired
    private IGisUserService iGisUserService;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    @Autowired
    private TokenEndpoint tokenEndpoint;

    /**
     * 用户注册
     * @param gisUser
     * @param result
     * @return
     */
    @RequestMapping(method = RequestMethod.POST,value = "/register")
    public Results register(@Validated @RequestBody GisUser gisUser, BindingResult result){
        Results results = new Results();

        if (result.hasErrors()) {
            // 0.处理验证错误
            results.setRet(97);
            results.setMsg(DATA_VALIDATE_FAILED);
            results.setSuccess(false);
            results.setResults(Collections.singletonList(result.getAllErrors()));
            return results;
        }
        try
        {
            // 1.用户名、Email、手机号重复校验
            String duplicate = isAccountAlreadyExists(gisUser);
            if(duplicate != null) {
                results.setSuccess(false);
                results.setRet(96);
                results.setMsg(duplicate);
                return results;
            }
            // 2.注册后初始为非pro用户
            gisUser.setIsprouser(false);
            // 3.密码加密(BCrypt)
            gisUser.setPassword(passwordEncoder.encode(gisUser.getPassword()));
            // 4.插入数据
            int i = iGisUserService.register(gisUser);
            if (i == 1) {
                results.setSuccess(true);
                results.setRet(1);
                results.setMsg(REGISTER_SUCCESS);
            } else {
                results.setSuccess(false);
                results.setRet(98);
                results.setMsg(SERVER_PROCESSING_FAILED);
            }
        } catch (Exception e){
            e.printStackTrace();
            results.setSuccess(false);
            results.setRet(99);
            results.setMsg(SERVER_PROCESSING_FAILED);
        }
        return results;
    }

    /**
     * 用户登录
     * @param gisUser
     * @param result
     * @return
     */
    @RequestMapping(method = RequestMethod.POST,value = "/signin")
    public Results signIn(@Validated @RequestBody GisUser gisUser, BindingResult result){
        Results results = new Results();
        if (result.hasErrors()) {
            // 0.处理验证错误
            results.setRet(97);
            results.setMsg(DATA_VALIDATE_FAILED);
            results.setSuccess(false);
            results.setResults(Collections.singletonList(result.getAllErrors()));
            return results;
        }
        try
        {
            // 1.查询数据库
            GisUser user = iGisUserService.getUserByUserName(gisUser.getUsername());
            // 2.用户是否存在
            if(user == null){
                results.setSuccess(false);
                results.setRet(0);
                results.setMsg(USER_NO_EXIST);
                return results;
            }
            // 3.匹配密码
            if(!passwordEncoder.matches(gisUser.getPassword(),user.getPassword())){
                results.setSuccess(false);
                results.setRet(2);
                results.setMsg(WRONG_PASSWORD);
                return results;
            }
            // 4.授权服务
            User clientDetails = new User("c1", "secret", new ArrayList<>());
            Authentication token = new UsernamePasswordAuthenticationToken(clientDetails, null, new ArrayList<>());
            //构建密码登录
            Map<String, String> map = new HashMap<>();
            map.put("username", user.getUsername());
            map.put("password", gisUser.getPassword());
            map.put("grant_type", "password");

            try {
                OAuth2AccessToken oAuth2AccessToken = tokenEndpoint.postAccessToken(token, map).getBody();
                results.setSuccess(true);
                results.setRet(1);
                results.setMsg(SIGNIN_SUCCESS);
                // 设置返回token
                Map<String,Object> tokenmap = new HashMap<>();
                tokenmap.put("token",oAuth2AccessToken);
                results.setData(tokenmap);
                return results;
            } catch (Exception e) {
                e.printStackTrace();
                results.setSuccess(false);
                results.setRet(3);
                results.setMsg(AUTHORIZATION_ERROR);
                return results;
            }

        } catch (Exception e){
            e.printStackTrace();
            results.setSuccess(false);
            results.setRet(99);
            results.setMsg(SERVER_PROCESSING_FAILED);
        }
        return results;
    }

    /**
     * 检查token
     * @return
     */
    @RequestMapping(method = RequestMethod.POST,value = "/checktoken")
    public Results CheckToken(String token){
        Results results = new Results();
        results.setSuccess(true);
        return results;
    }


    /**
     * 获取用户信息
     * @return
     */
    @RequestMapping(method = RequestMethod.POST,value = "/info")
    public Results userInfo(){
        Results results = new Results();
        try
        {
            GisUser user= iGisUserService.getUserByUserName(SecurityUtils.getUsername());
            if(user !=null){
                Map<String,Object> userinfo = new HashMap<>();
                user.setPassword(null);
                userinfo.put("userinfo",user);
                results.setRet(1);
                results.setSuccess(true);
                results.setMsg(USER_INFO_SUCCESS);
                results.setData(userinfo);
                return results;
            } else {
                results.setSuccess(false);
                results.setRet(99);
                results.setMsg(USER_INFO_FAILED);
                return results;
            }
        } catch (Exception e){
            e.printStackTrace();
            results.setSuccess(false);
            results.setRet(99);
            results.setMsg(USER_INFO_FAILED);
        }
        return results;
    }



    /**
     * 账户是否重复
     * @param gisUser
     * @return
     */
    private String isAccountAlreadyExists(GisUser gisUser){
        int a = iGisUserService.isusernameAlreadyExists(gisUser);
        if(a==1) {
            return DUPLICATE_USERNAME;
        }
        int b = iGisUserService.isphoneAlreadyExists(gisUser);
        if(b==1) {
            return DUPLICATE_PHONE;
        }
        int c = iGisUserService.isemailAlreadyExists(gisUser);
        if(c==1) {
            return DUPLICATE_EMAIL;
        }  else {
            return null;
        }
    }

}

