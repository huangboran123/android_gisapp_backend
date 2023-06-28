package com.utum.mobilegis.uaa.configuration;

import com.utum.mobilegis.uaa.service.UserOAuthDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

/**
 * @创建时间 : 2023/6/27
 * @作者 : huangboran
 * @类描述 : SpringSecurity配置
 **/
@Configuration
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserOAuthDetailsService userDetailsService;


    /**
     * BCrypt是一种基于哈希函数的密码哈希算法，它的设计目标是增加计算成本，使得暴力破解攻击变得更加困难和耗时。BCrypt算法在计算哈希值时会自动加入随机的salt（盐值），并且可以通过调整工作因子（work factor）来控制计算哈希值所需的时间和资源。
     * BCryptPasswordEncoder使用BCrypt算法对密码进行哈希处理，并自动处理salt和工作因子。在存储密码时，它会将哈希值和相关的salt一起存储，以便在验证密码时使用相同的salt和工作因子来计算哈希值，并将其与存储的哈希值进行比较来验证密码的正确性。
     * BCryptPasswordEncoder提供了安全且可靠的密码加密和验证机制，可以有效防止常见的密码攻击，如彩虹表攻击和暴力破解攻击。它是现代应用中广泛使用的密码加密方式之一。
     * @return
     */
    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.addAllowedOrigin("*"); // 允许所有来源
        configuration.addAllowedMethod("*"); // 允许所有HTTP方法
        configuration.addAllowedHeader("*"); // 允许所有请求头
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    /**
     * 请求获取用户相关权限信息
     * @return
     * @throws Exception
     */
    @Bean
    UserPackagFilter userPackagFilter() throws Exception {
        return new UserPackagFilter(authenticationManager());
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    /*
     * 不需要身份验证的url
     * */
    private static final String[] URL_WHITELIST = {
            "/user/signin",
            "/user/register",
            "/user/rsaToken"
    };


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.cors().and() // 启用跨域支持
                .csrf().disable()  // 禁用CSRF保护
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests() //验证请求
                .antMatchers(URL_WHITELIST).permitAll() // 不需要验证的url
                .anyRequest().authenticated()  // 其他需要认证
                .and()
                .addFilter(userPackagFilter())  // 添加过滤器
                .formLogin(); // 启用表单登录
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
    }
}
