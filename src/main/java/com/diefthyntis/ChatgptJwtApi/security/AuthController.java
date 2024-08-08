/*
 =================================================================================
 Ce contrôleur gère deux opérations principales :

    Connexion des utilisateurs (/signin):
        Authentifie l'utilisateur.
        Génère et renvoie un token JWT avec les détails de l'utilisateur.

    Inscription des utilisateurs (/signup):
        Vérifie si le nom d'utilisateur et l'email sont uniques.
        Crée un nouvel utilisateur avec des rôles appropriés.
        Sauvegarde l'utilisateur dans la base de données.
        Renvoie un message de succès.

Le code utilise les bonnes pratiques de sécurité de Spring, 
comme l'encodage des mots de passe et l'utilisation de tokens JWT pour la gestion des sessions utilisateur.
 =================================================================================
 */


/*
 @RestController: 
 Indique que cette classe est un contrôleur REST où chaque méthode renvoie un objet JSON.
 
 @RequestMapping("/api/auth"): 
 Indique que toutes les requêtes à cette classe auront un préfixe d'URL /api/auth.
 
 
 Injections de dépendances

    @Autowired AuthenticationManager authenticationManager: Gestionnaire d'authentification de Spring Security.
    @Autowired UserRepository userRepository: Répertoire pour les opérations sur les utilisateurs.
    @Autowired RoleRepository roleRepository: Répertoire pour les opérations sur les rôles.
    @Autowired PasswordEncoder encoder: Encodeur de mot de passe pour chiffrer les mots de passe des utilisateurs.
    @Autowired JwtUtils jwtUtils: Utilitaire pour générer des tokens JWT.
 */

 /*
   Méthode authenticateUser

    @PostMapping("/signin"): Cette méthode est appelée lorsqu'une requête POST est envoyée à /api/auth/signin.
    @Valid @RequestBody LoginRequest loginRequest: La requête de connexion est validée et mappée à l'objet LoginRequest.
    La méthode authentifie l'utilisateur avec le AuthenticationManager.
    Si l'authentification réussit, un token JWT est généré.
    Les détails de l'utilisateur (nom, email, rôles) sont extraits et renvoyés avec le token dans la réponse.
   */
  
  
  /*
   <?> se nomme Wildcard
   <?> permet de ne pas qualifier le type des instances de classes contenues dans la liste ?
   */

 /*
  Méthode registerUser

    @PostMapping("/signup"): Cette méthode est appelée lorsqu'une requête POST est envoyée à /api/auth/signup.
    @Valid @RequestBody SignupRequest signUpRequest: La requête d'inscription est validée et mappée à l'objet SignupRequest.
    La méthode vérifie si le nom d'utilisateur ou l'email existe déjà dans la base de données.
    Si le nom d'utilisateur ou l'email est déjà utilisé, une réponse d'erreur est renvoyée.
    Sinon, un nouvel utilisateur est créé et son mot de passe est encodé.
    Les rôles sont attribués à l'utilisateur en fonction de la demande (par défaut, ROLE_USER).
    L'utilisateur est sauvegardé dans la base de données.
    Une réponse de succès est renvoyée.
   */
package com.diefthyntis.ChatgptJwtApi.security;


import java.util.List;

import java.util.stream.Collectors;

import jakarta.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


import com.diefthyntis.ChatgptJwtApi.model.User;
import com.diefthyntis.ChatgptJwtApi.repository.UserRepository;


@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {
  @Autowired
  AuthenticationManager authenticationManager;

  @Autowired
  UserRepository userRepository;

 

  @Autowired
  PasswordEncoder encoder;

  @Autowired
  JwtUtils jwtUtils;

  @PostMapping("/signin")
  public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

    Authentication authentication = authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

    SecurityContextHolder.getContext().setAuthentication(authentication);
    String jwt = jwtUtils.generateJwtToken(authentication);
    
    User userDetails = (User) authentication.getPrincipal();    
    List<String> roles = userDetails.getAuthorities().stream()
        .map(item -> item.getAuthority())
        .collect(Collectors.toList());

    return ResponseEntity.ok(new JwtResponse(jwt, 
            userDetails.getId(), 
            userDetails.getUsername()));
  }

  @PostMapping("/signup")
  public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
    if (userRepository.existsByUsername(signUpRequest.getUsername())) {
      return ResponseEntity.badRequest().body(new MessageResponse("Error: Username is already taken!"));
    }

    if (userRepository.existsByEmail(signUpRequest.getEmail())) {
      return ResponseEntity.badRequest().body(new MessageResponse("Error: Email is already in use!"));
    }

    // Create new user's account
    User user = new User(signUpRequest.getUsername(),
                         encoder.encode(signUpRequest.getPassword()));

   
    userRepository.save(user);

    return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
  }

  
}
