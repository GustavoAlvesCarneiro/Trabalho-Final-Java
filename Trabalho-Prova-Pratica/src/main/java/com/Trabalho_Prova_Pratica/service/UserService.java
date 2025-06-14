package com.Trabalho_Prova_Pratica.service;

import com.Trabalho_Prova_Pratica.dto.RegisterRequest;
import com.Trabalho_Prova_Pratica.model.Role;
import com.Trabalho_Prova_Pratica.model.User;
import com.Trabalho_Prova_Pratica.repository.RoleRepository;
import com.Trabalho_Prova_Pratica.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository, RoleRepository roleRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional
    public User registerUser(RegisterRequest request) {
        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new RuntimeException("O email foi cadastrado!");
        }

        String rawRoleName = request.getRoleName();
        final String roleToAssign;

        if (rawRoleName != null && !rawRoleName.isEmpty()) {
            roleToAssign = rawRoleName.toUpperCase().startsWith("ROLE_") ? rawRoleName.toUpperCase() : "ROLE_" + rawRoleName.toUpperCase();
        } else {
            roleToAssign = "ROLE_USER";
        }

        Role role = roleRepository.findByName(roleToAssign)
                .orElseGet(() -> {
                    Role newRole = new Role();
                    newRole.setName(roleToAssign);
                    return roleRepository.save(newRole);
                });

        Set<Role> roles = new HashSet<>();
        roles.add(role);

        User newUser = new User();
        newUser.setName(request.getName());
        newUser.setEmail(request.getEmail());
        newUser.setPassword(passwordEncoder.encode(request.getPassword()));
        newUser.setRoles(roles);

        return userRepository.save(newUser);
    }

    public List<User> getAllUsers() {
        return userRepository.findAll();
    }

    public Optional<User> findUserById(Long id) {
        return userRepository.findById(id);
    }

    public Optional<User> findUserByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    @Transactional
    public User updateUser(Long id, RegisterRequest request) {
        return userRepository.findById(id).map(existingUser -> {
            if (request.getName() != null && !request.getName().isEmpty()) {
                existingUser.setName(request.getName());
            }
            if (request.getPassword() != null && !request.getPassword().isEmpty()) {
                existingUser.setPassword(passwordEncoder.encode(request.getPassword()));
            }

            return userRepository.save(existingUser);
        }).orElseThrow(() -> new RuntimeException("Usuário não encontrado com o seguinte ID: " + id));
    }

    public void deleteUser(Long id) {
        if (!userRepository.existsById(id)) {
            throw new RuntimeException("Usuário não encontrado com o seguinte ID: " + id);
        }
        userRepository.deleteById(id);
    }

    @Transactional
    public User assignRoleToUser(Long userId, String roleName) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("Usuário não encontrado com o seguinte ID: " + userId));

        final String formattedRoleName = roleName.toUpperCase().startsWith("ROLE_") ? roleName.toUpperCase() : "ROLE_" + roleName.toUpperCase();

        Role role = roleRepository.findByName(formattedRoleName)
                .orElseGet(() -> {
                    Role newRole = new Role();
                    newRole.setName(formattedRoleName);
                    return roleRepository.save(newRole);
                });

        user.getRoles().add(role);
        return userRepository.save(user);
    }
}
