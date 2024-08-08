package com.diefthyntis.ChatgptJwtApi.repository;


import org.springframework.data.jpa.repository.JpaRepository;

import org.springframework.stereotype.Repository;

import com.diefthyntis.ChatgptJwtApi.model.User;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    
    User findByUsername(String username);

	boolean existsByUsername(String username);

	boolean existsByEmail(String email);

    // Vous pouvez ajouter d'autres méthodes personnalisées si nécessaire
}
