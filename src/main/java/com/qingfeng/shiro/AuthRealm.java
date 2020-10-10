package com.qingfeng.shiro;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.apache.commons.collections.CollectionUtils;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.PrincipalCollection;
import org.springframework.beans.factory.annotation.Autowired;

import com.qingfeng.model.Permission;
import com.qingfeng.model.Role;
import com.qingfeng.model.User;
import com.qingfeng.service.UserService;
/**
 * 认证和授权
 * @author Administrator
 *
 */
public class AuthRealm extends AuthorizingRealm {


	@Autowired
	private UserService userService;
	
    /**
     * 给当前用户授权的权限（功能权限、角色）
     * @param principal
     * @return
     */
	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
		// 获取session中登录用户的用户(得到主要的身份)
        User user =(User) principals.getPrimaryPrincipal();
         //创建一个空的权限permissionList集合
        List<String> permissionList = new ArrayList<>();
        //创建一个空的角色roleNameList集合
        List<String> roleNameList = new ArrayList<>();
        //从当前用户获取角色的集合
        Set<Role> roleSet = user.getRoles();
        //判断当前用户获取角色的集合不为空
        if (CollectionUtils.isNotEmpty(roleSet)) {
        	//遍历角色的集合
            for(Role role : roleSet) {
            	//将角色添加到roleNameList集合中
                roleNameList.add(role.getRname());
               //从当前角色中获取权限集合
                Set<Permission> permissionSet = role.getPermissions();
              //判断当前角色获取权限的集合不为空
                if (CollectionUtils.isNotEmpty(permissionSet)) {
                	//遍历权限集合
                    for (Permission permission : permissionSet) {
                    	//将权限添加到权限permissionList集合中
                        permissionList.add(permission.getName());
                    }
                }
            }
        }
        //添加角色和权限
        SimpleAuthorizationInfo simpleAuthorizationInfo  = new SimpleAuthorizationInfo();
        simpleAuthorizationInfo .addStringPermissions(permissionList);
        simpleAuthorizationInfo .addRoles(roleNameList);
        return simpleAuthorizationInfo ;
	}

	   /**
     * 认证.登录
     */
	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
		// 实际上这个token是从LoginController里面loginUser.login(token)传过来的
		UsernamePasswordToken usernamePasswordToken = (UsernamePasswordToken)token;
		String username = usernamePasswordToken.getUsername();
		User user = userService.findByUsername(username);
		if(user==null) {
			return null;
		}
		//将用户存放到session中
		Session session = SecurityUtils.getSubject().getSession();
		session.setAttribute("user", user);
		
		// 进行认证，将正确数据给shiro处理
        // 密码不用自己比对，AuthenticationInfo认证信息对象，一个接口，new他的实现类对象SimpleAuthenticationInfo
		//这里验证authenticationToken和simpleAuthenticationInfo的信息
		AuthenticationInfo authentication = new SimpleAuthenticationInfo(user, user.getPassword(), this.getClass().getName());

        // 清缓存中的授权信息，保证每次登陆 都可以重新授权。因为AuthorizingRealm会先检查缓存有没有 授权信息，再调用授权方法
        super.clearCachedAuthorizationInfo(authentication.getPrincipals());
        // 设置会话超时的时间
        SecurityUtils.getSubject().getSession().setTimeout(-1000l);
		
		return authentication;
	}

}
