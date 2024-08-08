package com.diefthyntis.ChatgptJwtApi.security;



import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


import com.diefthyntis.ChatgptJwtApi.service.UserService;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

	/*
	 * userDetailsService : Injecte un service personnalisé (UserDetailsServiceImpl)
	 * qui est utilisé pour charger les détails de l'utilisateur lors de
	 * l'authentification.
	 */
	@Autowired
	UserService userService;

	
	@Bean
	public AuthTokenFilter authenticationJwtTokenFilter() {
		return new AuthTokenFilter();
	}

	
	@Bean
	public DaoAuthenticationProvider authenticationProvider() {
		DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();

		authProvider.setUserDetailsService(userService);
		authProvider.setPasswordEncoder(passwordEncoder());

		return authProvider;
	}

	
	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
		return authConfig.getAuthenticationManager();
	}

	
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	/*
	 * csrf.disable() : Désactive la protection CSRF. Ceci est souvent fait pour les
	 * API REST, car les tokens JWT sont utilisés pour sécuriser les requêtes.
	 * 
	 * exceptionHandling().authenticationEntryPoint(unauthorizedHandler) : Configure
	 * un point d'entrée d'authentification personnalisé (unauthorizedHandler) pour
	 * gérer les erreurs d'authentification, comme les tentatives d'accès non
	 * autorisées.
	 * 
	 * sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) :
	 * Configure la gestion des sessions pour ne pas créer de sessions côté serveur.
	 * Cela convient aux API REST stateless où les tokens JWT sont utilisés pour
	 * maintenir l'état de l'utilisateur.
	 * 
	 * authorizeHttpRequests(auth -> ...) :
	 * 
	 * Permet l'accès à toutes les requêtes correspondant aux chemins /api/auth/**
	 * et /api/test/** sans authentification. Exige une authentification pour toutes
	 * les autres requêtes (anyRequest().authenticated()).
	 * 
	 * authenticationProvider(authenticationProvider()) : Intègre le fournisseur
	 * d'authentification personnalisé dans la configuration de Spring Security.
	 * 
	 * addFilterBefore(authenticationJwtTokenFilter(),
	 * UsernamePasswordAuthenticationFilter.class) : Ajoute le filtre JWT
	 * (AuthTokenFilter) avant le filtre d'authentification par nom d'utilisateur et
	 * mot de passe standard (UsernamePasswordAuthenticationFilter). Cela permet au
	 * filtre JWT de traiter les requêtes avant le traitement d'authentification
	 * standard.
	 */
	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http.csrf(csrf -> csrf.disable())
				.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
				.authorizeHttpRequests(auth -> auth.requestMatchers("/api/auth/**").permitAll()
						.requestMatchers("/api/test/**").permitAll().anyRequest().authenticated());

		http.authenticationProvider(authenticationProvider());

		http.addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class);

		return http.build();
	}
}
