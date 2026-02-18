package com.vikas.filter;

import java.io.IOException;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.vikas.util.JWTValidator;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Class      : JwtAuthenticationFilter
 * Description: [Add brief description here]
 * Author     : Vikas Yadav
 * Created On : Feb 18, 2026
 * Version    : 1.0
 */
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

	@Autowired
	private JWTValidator jwt;
	
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		// 1. get uri
		String path = request.getServletPath();
		System.out.println("Gateway Path: " + path);

		// Public endpoint
		  if (path.startsWith("/api/auth/".trim())) {
		        filterChain.doFilter(request, response);
		        return;
		    }

		//2. get authHeader from the request
		String authHeader = request.getHeader("Authorization");

		if (authHeader == null || !authHeader.startsWith("Bearer ")) {
			sendError(response, "Missing or Invalid Authorization Header");
			response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			return;
		}

		//3. get token from the header
		String token = authHeader.substring(7);

		if (!jwt.isTokenValid(token)) {
			sendError(response, "Invalid Token");
			response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			return;
		}

		//4. get user information from token and role
		String username = jwt.extractUsername(token);
		String role = jwt.extractRole(token);

		System.out.println("username = " + username);
		System.out.println("role = " + role);

		//5. put roles in authorities
		List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("ROLE_" + role.trim()));
		System.out.println("Role from token: " + role);

		//6. put authenticated users object in SecurityContext so that it will work for @PreAuthorize, @Secured or Authentication
		UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(username, null,
				authorities);

		SecurityContextHolder.getContext().setAuthentication(authentication);

		filterChain.doFilter(request, response);
	}

	private void sendError(HttpServletResponse response, String message) throws IOException {

		response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
		response.setContentType("application/json");

		response.getWriter().write("""
				    {
				      "status": 401,
				      "error": "Unauthorized",
				      "message": "%s"
				    }
				""".formatted(message));
	}
}
