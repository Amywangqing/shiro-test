package com.qingfeng.shiro.config;

import java.util.LinkedHashMap;
import java.util.Map;

import javax.servlet.Filter;

import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.springframework.aop.framework.autoproxy.DefaultAdvisorAutoProxyCreator;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.qingfeng.shiro.AuthRealm;
import com.qingfeng.shiro.CredentialsMatcher;

/**
 * shiro的核心配置类
 * @author Administrator
 */
@Configuration
public class ShiroConfiguration {
	
	@Bean(name="shiroFilter")
    public ShiroFilterFactoryBean shiroFilter(@Qualifier("securityManager") SecurityManager manager) {
			
		ShiroFilterFactoryBean bean = new ShiroFilterFactoryBean();
			// 安全管理器，必须设置 SecurityManager
		     bean.setSecurityManager(manager);
		     
		   //添加Shiro内置过滤器
				/**
				 * Shiro内置过滤器，可以实现权限相关的拦截器
				 *    常用的过滤器：
				 *       anon: 无需认证（登录）可以访问
				 *       authc: 必须认证才可以访问
				 *       user: 如果使用rememberMe的功能可以直接访问
				 *       perm： 该资源必须得到资源权限才可以访问
				 *       role: 该资源必须得到角色权限才可以访问
				 */
		     // 配置登录的url地址
	        // 如果不设置默认会自动寻找Web工程根目录下的"/login.html"页面
	        bean.setLoginUrl("/toLogin");
	        // 登录成功的url地址
	        bean.setSuccessUrl("/index");
	        // 没有权限访问的，认证不通过的url地址
	        bean.setUnauthorizedUrl("/noAuth");
	        
	        // 过滤链定义，从上向下顺序执行，一般将 /**放在最为下边
	        // 配置访问权限 顺序判断
	        LinkedHashMap<String, String> filterChainDefinitionMap = new LinkedHashMap<>();
	        
	     // anon表示可以匿名访问url地址
	        filterChainDefinitionMap.put("/toLogin", "anon");
	        filterChainDefinitionMap.put("/login", "anon");
	        filterChainDefinitionMap.put("/logout", "anon");
	        //druid数据源可以匿名访问url地址
	        filterChainDefinitionMap.put("/druid/*", "anon");
	        
	        // authc表示需要认证才可以访问url地址
	        filterChainDefinitionMap.put("/index", "authc");
	        
	     // 配置某个url需要某个角色才能访问,/hello只能该用户有admin角色才能访问
	        filterChainDefinitionMap.put("/hello", "roles[admin]");
	        
	     // 配置某个url需要某个权限才能访问,/update只能该用户有update权限才能访问
	      filterChainDefinitionMap.put("/update", "perms[update]");
	      
	      //用户拦截器，用户已经身份验证/记住我登录的都可；
	      //filterChainDefinitionMap.put("/**", "user");
	        
	        bean.setFilterChainDefinitionMap(filterChainDefinitionMap);
	        return bean;

	}
	
	@Bean(name="securityManager")
	public 	SecurityManager securityManager(@Qualifier("authRealm") AuthRealm authRealm) {
	        DefaultWebSecurityManager manager = new DefaultWebSecurityManager();
	        manager.setRealm(authRealm);
	        return manager;
	}
	
	
	/**
	 * 创建Realm
	 * @Qualifier限定描述符除了能根据名字进行注入，更能进行更细粒度的控制如何选择候选者，具体使用方式如下：
	 *	@Qualifier(value = "限定标识符")  
	 *	字段、方法、参数
	 */
	@Bean(name="authRealm")
	public AuthRealm authRealm(@Qualifier ("credentialsMatcher") CredentialsMatcher credentialsMatcher) {
		AuthRealm authRealm = new AuthRealm();
		//在Realm设置自己的密码比较器
		authRealm.setCredentialsMatcher(credentialsMatcher);
		return authRealm;
		
	}
		
	// 配置自定义的密码比较器
	@Bean(name="credentialsMatcher")
	public CredentialsMatcher credentialsMatcher() {
		return new CredentialsMatcher();
	}
	
	/**
	 * shiro与securityManager进行管理
	 * @param manager
	 * @return
	 */
	@Bean
    public AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor(@Qualifier("securityManager") SecurityManager manager) {
        AuthorizationAttributeSourceAdvisor advisor = new AuthorizationAttributeSourceAdvisor();
        advisor.setSecurityManager(manager);
        return advisor;
    }
	
	/**
	 * 开启代理
	 * @return
	 */
	@Bean
    public DefaultAdvisorAutoProxyCreator defaultAdvisorAutoProxyCreator() {
        DefaultAdvisorAutoProxyCreator creator = new DefaultAdvisorAutoProxyCreator();
        creator.setProxyTargetClass(true);
        return creator;
    }
	

}
