package com.qingfeng.controller;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import com.qingfeng.model.User;

@Controller
public class ShiroTestController {
	
	/**
	 * 跳转到登录页面
	 * @return
	 */
	@RequestMapping("/toLogin")
	public String toLogin(){
		return "/login";
	}

	/**
	 * 进行登录
	 * @param username  用户名：admin
	 * @param password 密码：123456
	 * @param model
	 * @return
	 */
	@RequestMapping("/login")
	public String login(@RequestParam("username") String username,
											@RequestParam("password") String password,
											Model model) {
		//判断username和password是否为空
		
		/**
		 * 使用Shiro编写认证操作,用户认证信息
		 */
		//1.获取Subject
		Subject subject = SecurityUtils.getSubject();
		
		//2.封装用户数据
		UsernamePasswordToken usernamePasswordToken = new UsernamePasswordToken(username,password);
		try {
			//3.执行登录方法
			subject.login(usernamePasswordToken);
			//4.获取登录用户，主体
			User user = (User)subject.getPrincipal();
			model.addAttribute("username", user.getUsername());
			//登录成功
			//跳转到index.html
			return "index";
		} catch (UnknownAccountException e) {
			//e.printStackTrace();
			//登录失败:用户名不存在
			model.addAttribute("msg", "用户名不存在");
			return "login";
		}catch (IncorrectCredentialsException e) {
			//e.printStackTrace();
			//登录失败:密码错误
			model.addAttribute("msg", "密码错误");
			return "login";
		}
	}
	
	@RequestMapping("/index")
	public String index(){
		return "/index";
	}
	
	/**
	 * /hello设置了只能该用户有admin角色才能访问
	 * @return
	 */
	@RequestMapping("/hello")
	@ResponseBody
	public String hello() {
		return "Helle Test";
	}
	/**
	 * /update设置了只能该用户有update权限才能访问
	 * @return
	 */
	@RequestMapping("/update")
	@ResponseBody
	public String update() {
		return "update OK";
	}
	
	/**
	 * 跳转到无权限访问页面
	 * @return
	 */
	@RequestMapping("/noAuth")
	public String noAuth(){
		return "/noAuth";
	}
	
	/**
	 * 退出登录
	 * @param session
	 * @return
	 */
	@RequestMapping("/logout")
    public String logout(HttpSession session) {
        Subject subject = SecurityUtils.getSubject();
        if (subject.isAuthenticated()) {
            User user = (User) subject.getPrincipal();
            subject.logout(); // session 会销毁，在SessionListener监听session销毁，清理权限缓存
        }
        return "toLogin";
    }
	
	
}
