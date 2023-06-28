package com.utum.mobilegis.mapper;

import com.utum.mobilegis.domain.GisUser;
import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Select;

@Mapper
public interface GisUserMapper {

    @Insert("insert into gis_user values (null,#{username},#{email},#{phone},#{password},#{isprouser},CURRENT_TIMESTAMP())")
    int register(GisUser gisUser);

    @Select("select count(*) from gis_user where username = #{username} ")
    int isusernameAlreadyExists(GisUser gisUser);

    @Select("select count(*) from gis_user where email = #{email} ")
    int isemailAlreadyExists(GisUser gisUser);

    @Select("select count(*) from gis_user where phone = #{phone} ")
    int isphoneAlreadyExists(GisUser gisUser);

    @Select("select * from gis_user where username = #{username} or email = #{username} or  phone=#{username} ")
    GisUser getUserByUserName(String username);

    @Select("select * from gis_user where id =#{userId}")
    GisUser getUserByUserId(long userId);
}
