package com.dianping.cat.system.page.login.service;

import com.dianping.cat.system.page.login.spi.ISessionManager;
import org.apache.commons.lang.StringUtils;

import java.util.LinkedHashMap;
import java.util.Map;

public class SessionManager implements ISessionManager<Session, Token, Credential> {

	private static final Map<String, String> userPwd = new LinkedHashMap<>();

	@Override
	public Token authenticate(Credential credential) {
		String account = credential.getAccount();
		String password = credential.getPassword();

		if (account != null && password != null) {

			if (userPwd.size() == 0) {
				String users = System.getProperty("catusers");

				if (users == null || users.trim().length() == 0) {
					for (String userpassword : users.split(",")) {
						userPwd.put(StringUtils.substringBefore(userpassword, ":"), StringUtils.substringAfter(userpassword, ":"));
					}
				} else {
					userPwd.put("catadmin", "catadmin");
				}
			}

			if (!password.equals(userPwd.get(account))) {
				return null;
			}

			// default no authenticate
			return new Token(account, account);
		} else {
			return null;
		}
	}

	@Override
	public Session validate(Token token) {
		LoginMember member = new LoginMember();

		member.setUserName(token.getUserName());
		member.setRealName(token.getRealName());

		return new Session(member);
	}
}
