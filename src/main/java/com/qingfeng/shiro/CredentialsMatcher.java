package com.qingfeng.shiro;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authc.credential.SimpleCredentialsMatcher;
import org.apache.shiro.session.Session;

import com.qingfeng.model.User;
import com.qingfeng.util.MD5Util;

/**
 * 自定义shiro的密码比较器
 */
public class CredentialsMatcher extends SimpleCredentialsMatcher {


	/**
	 * 自定义matcher,这里就是对比用户的输入的信息封装成的token和按照用户输入的principal(一般就是用户名)
     *从数据库中查询出的信息封装的info信息,一般就是比对他们的Credentials
	 */
	@Override
	public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
		//将token转为UsernamePasswordToken类型的token
		UsernamePasswordToken usernamePasswordToken = (UsernamePasswordToken)token;
		//获取用户输入的密码
		String password = new String(usernamePasswordToken.getPassword());
		System.out.println("用户输入的密码:"+password);
		//获取数据库的密码
		//String dbPassword =(String)info.getCredentials();//如果只要密码，就可以用这个获取数据库密码
		
		// 如果要获得数据库中的密码和盐值，则在认证的时候存放到session中用户取出来，获取密码和盐值
		//将在认证的时候存放到session中用户取出来
		Session session = SecurityUtils.getSubject().getSession();
		User user =(User) session.getAttribute("user");
		//获取数据加密的密码
		String dbPassword = user.getPassword();
		//获取数据中的盐值
		String salt = user.getSalt();
		 System.out.println("user===========:"+user);
		 //将用输入的密码和盐值进行MD5加密
		 String MD5PassWord = MD5Util.MD5(password+salt);
		
		return this.equals(dbPassword,MD5PassWord);
	}
	

}
