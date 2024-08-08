/*
 =====================================================================================
 Ce code source définit une classe utilitaire pour la gestion des JSON Web Tokens (JWT) 
 dans une application Spring Boot avec des fonctionnalités de sécurité. 
 Voici une explication détaillée de ce que fait chaque partie du code :

    Imports :
        Les importations incluent des classes nécessaires pour manipuler les dates, la journalisation, 
        l'authentification, et la manipulation des JWT.

    Classe JwtUtils :
        La classe est annotée avec @Component, ce qui permet à Spring de la détecter et de la gérer en tant que bean.

    Logger :
        Un logger est défini pour enregistrer les messages d'erreur ou d'information.

    Propriétés :
        Deux propriétés sont injectées depuis le fichier de configuration (application.properties), 
        à savoir jwtSecret (la clé secrète utilisée pour signer les JWT) 
        et jwtExpirationMs (la durée de validité du token en millisecondes).

    Méthode generateJwtToken :
        Cette méthode génère un JWT en utilisant les informations d'authentification de l'utilisateur.
        Elle extrait le nom d'utilisateur des détails de l'utilisateur (UserDetailsImpl), 
        et utilise la bibliothèque io.jsonwebtoken pour créer un token avec :
            Le nom d'utilisateur comme sujet.
            La date actuelle comme date d'émission.
            Une date d'expiration calculée à partir de la date actuelle et de jwtExpirationMs.
            Le token est signé avec une clé générée à partir de jwtSecret en utilisant 
            l'algorithme HS256.

    Méthode key :
        Cette méthode génère une clé secrète à partir de jwtSecret 
        en le décodant avec l'algorithme BASE64 et en utilisant Keys.hmacShaKeyFor.

    Méthode getUserNameFromJwtToken :
        Cette méthode extrait le nom d'utilisateur (sujet) d'un token JWT.
        Elle parse le token en utilisant la clé secrète pour le valider et récupère le sujet
         (nom d'utilisateur) du corps du token.

    Méthode validateJwtToken :
        Cette méthode valide un token JWT.
        Elle essaie de parser le token avec la clé secrète et retourne true si le token est valide.
        En cas d'exception (token mal formé, expiré, non supporté 
        ou avec une chaîne de revendications vide), 
        elle capture l'exception, enregistre un message d'erreur, et retourne false.

En résumé, la classe JwtUtils fournit des méthodes pour générer des tokens JWT, extraire des informations d'un token, et valider les tokens. Ces utilitaires sont couramment utilisés dans des applications sécurisées pour authentifier les utilisateurs et gérer les sessions de manière stateless.
=========================================================================================
 */

package com.diefthyntis.ChatgptJwtApi.security;

import java.security.Key;
import java.util.Date;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import com.diefthyntis.ChatgptJwtApi.model.User;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtUtils {
  private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

  @Value("${bezkoder.app.jwtSecret}")
  private String jwtSecret;

  @Value("${bezkoder.app.jwtExpirationMs}")
  private int jwtExpirationMs;

  public String generateJwtToken(Authentication authentication) {

    User userPrincipal = (User) authentication.getPrincipal();

    return Jwts.builder()
        .setSubject((userPrincipal.getUsername()))
        .setIssuedAt(new Date())
        .setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
        .signWith(key(), SignatureAlgorithm.HS256)
        .compact();
  }
  
  private Key key() {
    return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
  }

  public String getUserNameFromJwtToken(String token) {
    return Jwts.parserBuilder().setSigningKey(key()).build()
               .parseClaimsJws(token).getBody().getSubject();
  }

  public boolean validateJwtToken(String authToken) {
    try {
      Jwts.parserBuilder().setSigningKey(key()).build().parse(authToken);
      return true;
    } catch (MalformedJwtException e) {
      logger.error("Invalid JWT token: {}", e.getMessage());
    } catch (ExpiredJwtException e) {
      logger.error("JWT token is expired: {}", e.getMessage());
    } catch (UnsupportedJwtException e) {
      logger.error("JWT token is unsupported: {}", e.getMessage());
    } catch (IllegalArgumentException e) {
      logger.error("JWT claims string is empty: {}", e.getMessage());
    }

    return false;
  }
}

