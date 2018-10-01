package es.milfist.security;

import es.milfist.user.User;
import es.milfist.user.UserCreator;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;

import static es.milfist.security.Constants.*;

public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

	private AuthenticationManager authenticationManager;

	public JWTAuthenticationFilter(AuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		try {
			return attemptAuthentication(request);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication auth) throws IOException, ServletException {
		response.addHeader(HEADER_AUTHORIZACION_KEY, TOKEN_BEARER_PREFIX + " " + getJsonWebToken(auth));
	}

	//TODO: REFACTOR Single resposibility principle
	private  Authentication attemptAuthentication(HttpServletRequest request) {
		String authorizationHeader = request.getHeader("Authorization");
		User user = new User();
		if (isCorrectHeader(authorizationHeader)) {
			String decodedCredentials = decodeBasicAuthorization(authorizationHeader);
			user = UserCreator.transformStringCredentialsToUsuario(decodedCredentials);
		}
		return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
				user.getUsername(), user.getPassword()));
	}


	private String getJsonWebToken(Authentication auth) {
		return Jwts.builder()
				.setIssuedAt(new Date())
				.setIssuer(ISSUER_INFO)
				.setSubject(((org.springframework.security.core.userdetails.User)auth.getPrincipal()).getUsername()
						.concat(extractConcatenatedRoles(auth)))
				.setExpiration(new Date(System.currentTimeMillis() + TOKEN_EXPIRATION_TIME))
				.signWith(SignatureAlgorithm.HS512, SUPER_SECRET_KEY).compact();
	}

	private boolean isCorrectHeader(String authorizationHeader) {
		return authorizationHeader != null && authorizationHeader.toLowerCase().startsWith("basic");
	}

	private String decodeBasicAuthorization(String authorizationHeader) {
		String base64Credentials = authorizationHeader.substring("Basic".length()).trim();
		byte[] credDecoded = Base64.getDecoder().decode(base64Credentials);
		return new String(credDecoded, StandardCharsets.UTF_8);
	}

	private String extractConcatenatedRoles(Authentication auth) {
		String concatenatedRoles = ":";
		for (GrantedAuthority role : auth.getAuthorities()) {
			concatenatedRoles = concatenatedRoles.concat(role.getAuthority().concat(ROLE_SEPARATOR));
		}
		return concatenatedRoles;
	}

}
