package com.utum.mobilegis.domain;

import lombok.Data;

import javax.validation.constraints.Email;
import javax.validation.constraints.Pattern;
import java.util.Date;


@Data
public class GisUser {
    private Long id;
    @Pattern(regexp = "^[a-zA-Z][a-zA-Z0-9_]{4,18}$",message = "用户名长度4~18 ,字母开头，允许字母数字下划线")
    private String username;
    @Email(message = "邮箱格式不正确")
    private String email;
    @Pattern(regexp = "^(?=.*\\d)(?=.*[a-z])(?=.*[A-Z]).{6,18}$",message = "密码长度6~18 ,必须包含大小写字母和数字的组合，可以使用特殊字符")
    private String password;
    @Pattern(regexp = "^1[3456789]\\d{9}$",message = "手机号码要符合中国大陆手机号")
    private String phone;
    private Boolean isprouser;
    private Date registertime;

}
