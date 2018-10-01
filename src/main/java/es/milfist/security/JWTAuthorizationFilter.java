package es.milfist.security;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.constraints.NotNull;

import es.milfist.usuario.User;
import es.milfist.usuario.UserCreator;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import io.jsonwebtoken.Jwts;

import static es.milfist.security.Constants.*;

public class JWTAuthorizationFilter extends BasicAuthenticationFilter {

	public JWTAuthorizationFilter(AuthenticationManager authManager) {
		super(authManager);
	}

	@Override
	protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
			throws IOException, ServletException {
		String header = req.getHeader(HEADER_AUTHORIZACION_KEY);
		if (header == null || !header.startsWith(TOKEN_BEARER_PREFIX)) {
			chain.doFilter(req, res);
		}
		UsernamePasswordAuthenticationToken authentication = getAuthentication(req);
		SecurityContextHolder.getContext().setAuthentication(authentication);
		chain.doFilter(req, res);
	}

	//TODO: REFACTOR Single resposibility principle
	private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) {
		UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = null;
		String token = getTokenFromRequest(request);
		String userRoles = getUserAndRolesFromToken(token);
		if (userRoles != null) {
			User user = UserCreator.getUsuarioFromDecodeInformation(userRoles);
			usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(user.getUsername(), null, getGrantedAuthorityList(user.getRole()));
		}

		return usernamePasswordAuthenticationToken;
	}

	private String getUserAndRolesFromToken(String token) {
		String userRoles = null;
		if (token != null) {
			userRoles = decodeTokenAndExtractUserRoles(token);
		}
		return userRoles;
	}

	private String getTokenFromRequest (HttpServletRequest request) {
		return request.getHeader(HEADER_AUTHORIZACION_KEY);
	}


	private String decodeTokenAndExtractUserRoles(@NotNull String token) {
		return Jwts.parser()
				.setSigningKey(SUPER_SECRET_KEY)
				.parseClaimsJws(token.replace(TOKEN_BEARER_PREFIX, ""))
				.getBody()
				.getSubject();
	}

	private List<GrantedAuthority> getGrantedAuthorityList(String role) {
		List<GrantedAuthority> grantedAuthorityList = new ArrayList<>();
		grantedAuthorityList.add(new SimpleGrantedAuthority(ROLE_PREFIX.concat(role)));
		return grantedAuthorityList;
	}

	private List<GrantedAuthority> getGrantedAuthorityList(String[] roles) {
		List<GrantedAuthority> grantedAuthorityList = new ArrayList<>();
		for (String role : roles) {
				grantedAuthorityList.add(new SimpleGrantedAuthority(ROLE_PREFIX.concat(role)));
		}
		return grantedAuthorityList;
	}
}
