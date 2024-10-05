package com.supply.mapper;

import com.supply.entity.IdentityAuthentication;
import com.supply.entity.User;
import org.apache.ibatis.annotations.*;

import java.time.LocalDateTime;
import java.util.List;

@Mapper
public interface UserMapper {

    /**
     * 用户注册
     *
     * @param user 用户注册信息
     */
    @Options(useGeneratedKeys = true, keyProperty = "id")
    @Insert("insert into user(username, firm_name, work_type, image, email, telephone, password, create_time, update_time,id_number)" +
            "values (#{username}, #{firmName}, #{workType}, #{image}, #{email}, #{telephone}, #{password}, #{createTime},#{updateTime}, #{idNumber})")
    void register(User user);

    /**
     * 将审核信息放入申请表
     *
     * @param identityAuthentication 申请信息
     */
    @Insert("insert into identity_authentication(user_id, work_type,id_number,images,application_time) values (#{userId},#{workType},#{idNumber},#{images},#{applicationTime})")
    void sendVerificationMessage(IdentityAuthentication identityAuthentication);

    /**
     * 用户重置密码
     *
     * @param user 用户信息
     * @param now  更改时间
     */
    @Update("update user set password = #{password},update_time = #{now} where email = #{email}")
    void resetPassword(User user, LocalDateTime now);

    /**
     * 用户登录
     *
     * @param user 用户登录信息
     * @return 比对后的用户信息
     */
    User login(User user);

    /**
     * 权限查询
     *
     * @param id 当前用户id
     * @return 权限信息
     */
    List<String> getAuthority(Long id);

    /**
     * 插入权限信息
     *
     * @param id       当前注册用户
     * @param workType 当前注册用户角色
     */
    @Insert("insert into user_role(user_id, role_id) VALUES (#{id},#{workType})")
    void setAuthority(Long id, Integer workType);

    /**
     * 根据用户id获取用户全部信息
     *
     * @param id 用户id
     * @return 用户信息
     */
    @Select("select * from user where id = #{id};")
    User getUserInformationById(Long id);

    /**
     * 将账户状态更改为可使用
     *
     * @param id  用户id
     * @param now 更改时间
     */
    @Update("update user set account_status = 1,update_time = #{now} where id = #{id}")
    void changeStatusToNormal(Long id, LocalDateTime now);

    /**
     * 将账户状态更改为审核失败
     *
     * @param id  用户id
     * @param now 更改时间
     */
    @Update("update user set account_status = 4,update_time = #{now} where id = #{id}")
    void changeStatusToCheckFailed(Long id, LocalDateTime now);

    /**
     * 封禁用户账号
     *
     * @param id  用户id
     * @param now 更改时间
     */
    @Update("update user set account_status = 2,update_time = #{now} where id = #{id}")
    void blockAccount(Long id, LocalDateTime now);

    /**
     * 查询所有通过身份认证的用户信息
     *
     * @return 用户信息
     */
    @Select("select * from user where (work_type = 1 or work_type = 2) and (account_status = 1 or account_status = 2)")
    List<User> getAllUsers();

    /**
     * 解封用户
     *
     * @param id  用户id
     * @param now 更改时间
     */
    @Update("update user set account_status = 1,update_time = #{now} where id = #{id}")
    void liftUser(Long id, LocalDateTime now);
}
