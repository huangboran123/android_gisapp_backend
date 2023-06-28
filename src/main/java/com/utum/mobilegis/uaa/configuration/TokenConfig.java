package com.utum.mobilegis.uaa.configuration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.provider.authentication.TokenExtractor;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
/**
 * @创建时间 : 2023/6/27
 * @作者 : huangboran
 * @类描述 : token配置
 **/
@Configuration
public class TokenConfig {

    private String SIGNING_KEY = "UTUM1009";

    @Bean
    public TokenStore tokenStore() {
        //JWT令牌存储方案
        return new JwtTokenStore(accessTokenConverter());
    }


    @Bean
    public JwtAccessTokenConverter accessTokenConverter() {
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        converter.setSigningKey(SIGNING_KEY); //对称秘钥，资源服务器使用该秘钥来验证
        return converter;
    }


//    @Bean
//    public TokenStore tokenStore() {
//        //使用内存存储令牌（普通令牌）
//        return new InMemoryTokenStore();
//    }
}

