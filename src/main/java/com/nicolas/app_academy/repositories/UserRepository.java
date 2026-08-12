package com.nicolas.app_academy.repositories;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.nicolas.app_academy.entities.User;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
  Optional<User> findUserByUserIdentifier(String userIdentifier);
}