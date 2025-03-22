## Vue d'ensemble de l'implémentation 2FA

Nous allons mettre en place une authentification à deux facteurs basée sur TOTP (Time-based One-Time Password) avec les éléments suivants :
1. Spring Boot pour le backend
2. Angular pour le frontend
3. La bibliothèque jOTP pour la génération et validation des codes TOTP

Commençons par créer le code nécessaire pour le backend et le frontend.

### Backend (Spring Boot)


```xml
<!-- 1. Ajoutez les dépendances Maven requises dans votre pom.xml -->
<!-- pom.xml -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-web</artifactId>
</dependency>
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-api</artifactId>
    <version>0.11.5</version>
</dependency>
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-impl</artifactId>
    <version>0.11.5</version>
    <scope>runtime</scope>
</dependency>
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-jackson</artifactId>
    <version>0.11.5</version>
    <scope>runtime</scope>
</dependency>
<dependency>
    <groupId>dev.samstevens.totp</groupId>
    <artifactId>totp</artifactId>
    <version>1.7.1</version>
</dependency>

```

```java

// 2. Créez le modèle d'utilisateur
// src/main/java/com/example/auth/model/User.java
package com.example.auth.model;

import javax.persistence.*;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "users")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String username;

    @Column(nullable = false)
    private String password;

    @Column(name = "mfa_enabled")
    private boolean mfaEnabled;

    @Column(name = "mfa_secret")
    private String mfaSecret;

    // Getters and setters
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public boolean isMfaEnabled() {
        return mfaEnabled;
    }

    public void setMfaEnabled(boolean mfaEnabled) {
        this.mfaEnabled = mfaEnabled;
    }

    public String getMfaSecret() {
        return mfaSecret;
    }

    public void setMfaSecret(String mfaSecret) {
        this.mfaSecret = mfaSecret;
    }
}

// 3. Créez le repository pour l'utilisateur
// src/main/java/com/example/auth/repository/UserRepository.java
package com.example.auth.repository;

import com.example.auth.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
    Boolean existsByUsername(String username);
}

// 4. Créez le service TOTP pour gérer la 2FA
// src/main/java/com/example/auth/service/TotpService.java
package com.example.auth.service;

import dev.samstevens.totp.code.*;
import dev.samstevens.totp.exceptions.QrGenerationException;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.qr.ZxingPngQrGenerator;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;
import org.springframework.stereotype.Service;

import static dev.samstevens.totp.util.Utils.getDataUriForImage;

@Service
public class TotpService {

    private final SecretGenerator secretGenerator = new DefaultSecretGenerator();
    private final QrGenerator qrGenerator = new ZxingPngQrGenerator();
    private final TimeProvider timeProvider = new SystemTimeProvider();
    private final CodeGenerator codeGenerator = new DefaultCodeGenerator();
    private final CodeVerifier codeVerifier = new DefaultCodeVerifier(codeGenerator, timeProvider);

    public String generateSecret() {
        return secretGenerator.generate();
    }

    public String getUriForImage(String secret, String username) {
        QrData data = new QrData.Builder()
                .label(username)
                .secret(secret)
                .issuer("VotreApplication")
                .algorithm(HashingAlgorithm.SHA1)
                .digits(6)
                .period(30)
                .build();
        return data.getUri();
    }

    public String generateQrCodeImageUri(String secret, String username) {
        QrData data = new QrData.Builder()
                .label(username)
                .secret(secret)
                .issuer("VotreApplication")
                .algorithm(HashingAlgorithm.SHA1)
                .digits(6)
                .period(30)
                .build();

        try {
            byte[] qrCodeImage = qrGenerator.generate(data);
            return getDataUriForImage(qrCodeImage, qrGenerator.getImageMimeType());
        } catch (QrGenerationException e) {
            throw new RuntimeException("Erreur lors de la génération du QR code", e);
        }
    }

    public boolean validateCode(String code, String secret) {
        return codeVerifier.isValidCode(secret, code);
    }
}

// 5. Créez les DTO pour l'authentification
// src/main/java/com/example/auth/payload/request/LoginRequest.java
package com.example.auth.payload.request;

public class LoginRequest {
    private String username;
    private String password;

    // Getters and setters
    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}

// src/main/java/com/example/auth/payload/request/VerifyCodeRequest.java
package com.example.auth.payload.request;

public class VerifyCodeRequest {
    private String username;
    private String code;

    // Getters and setters
    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }
}

// src/main/java/com/example/auth/payload/response/JwtResponse.java
package com.example.auth.payload.response;

public class JwtResponse {
    private String token;
    private String type = "Bearer";
    private Long id;
    private String username;
    private boolean mfaEnabled;
    private String qrCodeImage;

    public JwtResponse(String token, Long id, String username, boolean mfaEnabled) {
        this.token = token;
        this.id = id;
        this.username = username;
        this.mfaEnabled = mfaEnabled;
    }

    public JwtResponse(String token, Long id, String username, boolean mfaEnabled, String qrCodeImage) {
        this.token = token;
        this.id = id;
        this.username = username;
        this.mfaEnabled = mfaEnabled;
        this.qrCodeImage = qrCodeImage;
    }

    // Getters and setters
    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public boolean isMfaEnabled() {
        return mfaEnabled;
    }

    public void setMfaEnabled(boolean mfaEnabled) {
        this.mfaEnabled = mfaEnabled;
    }

    public String getQrCodeImage() {
        return qrCodeImage;
    }

    public void setQrCodeImage(String qrCodeImage) {
        this.qrCodeImage = qrCodeImage;
    }
}

// 6. Créez le contrôleur d'authentification
// src/main/java/com/example/auth/controller/AuthController.java
package com.example.auth.controller;

import com.example.auth.model.User;
import com.example.auth.payload.request.LoginRequest;
import com.example.auth.payload.request.SignupRequest;
import com.example.auth.payload.request.VerifyCodeRequest;
import com.example.auth.payload.response.JwtResponse;
import com.example.auth.payload.response.MessageResponse;
import com.example.auth.repository.UserRepository;
import com.example.auth.security.jwt.JwtUtils;
import com.example.auth.security.services.UserDetailsImpl;
import com.example.auth.service.TotpService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

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

    @Autowired
    TotpService totpService;

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        
        User user = userRepository.findByUsername(userDetails.getUsername())
                .orElseThrow(() -> new RuntimeException("Erreur: Utilisateur non trouvé."));

        if (user.isMfaEnabled()) {
            // Si 2FA est activé, nous ne générons pas de JWT tout de suite
            return ResponseEntity.ok(new JwtResponse(null, user.getId(), user.getUsername(), true));
        } else {
            // Si 2FA n'est pas activé, nous générons un JWT standard
            String jwt = jwtUtils.generateJwtToken(authentication);
            return ResponseEntity.ok(new JwtResponse(jwt, user.getId(), user.getUsername(), false));
        }
    }

    @PostMapping("/verify-code")
    public ResponseEntity<?> verifyCode(@RequestBody VerifyCodeRequest verifyRequest) {
        User user = userRepository.findByUsername(verifyRequest.getUsername())
                .orElseThrow(() -> new RuntimeException("Erreur: Utilisateur non trouvé."));

        if (totpService.validateCode(verifyRequest.getCode(), user.getMfaSecret())) {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(verifyRequest.getUsername(), user.getPassword()));
            
            SecurityContextHolder.getContext().setAuthentication(authentication);
            String jwt = jwtUtils.generateJwtToken(authentication);
            
            return ResponseEntity.ok(new JwtResponse(jwt, user.getId(), user.getUsername(), true));
        } else {
            return ResponseEntity.badRequest().body(new MessageResponse("Code invalide"));
        }
    }

    @PostMapping("/enable-2fa")
    public ResponseEntity<?> enable2FA(@RequestBody String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("Erreur: Utilisateur non trouvé."));

        // Générer un secret s'il n'en a pas déjà un
        if (user.getMfaSecret() == null || user.getMfaSecret().isEmpty()) {
            String secret = totpService.generateSecret();
            user.setMfaSecret(secret);
        }

        // Activer 2FA pour l'utilisateur
        user.setMfaEnabled(true);
        userRepository.save(user);

        // Générer un QR code pour l'utilisateur
        String qrCodeImage = totpService.generateQrCodeImageUri(user.getMfaSecret(), user.getUsername());

        return ResponseEntity.ok(new JwtResponse(null, user.getId(), user.getUsername(), true, qrCodeImage));
    }

    @PostMapping("/disable-2fa")
    public ResponseEntity<?> disable2FA(@RequestBody String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("Erreur: Utilisateur non trouvé."));

        user.setMfaEnabled(false);
        userRepository.save(user);

        return ResponseEntity.ok(new MessageResponse("2FA désactivé avec succès"));
    }
}

// 7. Créez la configuration de sécurité
// src/main/java/com/example/auth/security/WebSecurityConfig.java
package com.example.auth.security;

import com.example.auth.security.jwt.AuthEntryPointJwt;
import com.example.auth.security.jwt.AuthTokenFilter;
import com.example.auth.security.services.UserDetailsServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    UserDetailsServiceImpl userDetailsService;

    @Autowired
    private AuthEntryPointJwt unauthorizedHandler;

    @Bean
    public AuthTokenFilter authenticationJwtTokenFilter() {
        return new AuthTokenFilter();
    }

    @Override
    public void configure(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
        authenticationManagerBuilder.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.cors().and().csrf().disable()
            .exceptionHandling().authenticationEntryPoint(unauthorizedHandler).and()
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
            .authorizeRequests()
            .antMatchers("/api/auth/**").permitAll()
            .anyRequest().authenticated();

        http.addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class);
    }
}

// 8. Créez les classes JWT
// src/main/java/com/example/auth/security/jwt/JwtUtils.java
package com.example.auth.security.jwt;

import com.example.auth.security.services.UserDetailsImpl;
import io.jsonwebtoken.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class JwtUtils {
    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    @Value("${app.jwtSecret}")
    private String jwtSecret;

    @Value("${app.jwtExpirationMs}")
    private int jwtExpirationMs;

    public String generateJwtToken(Authentication authentication) {
        UserDetailsImpl userPrincipal = (UserDetailsImpl) authentication.getPrincipal();

        return Jwts.builder()
                .setSubject((userPrincipal.getUsername()))
                .setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
                .signWith(SignatureAlgorithm.HS512, jwtSecret)
                .compact();
    }

    public String getUserNameFromJwtToken(String token) {
        return Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody().getSubject();
    }

    public boolean validateJwtToken(String authToken) {
        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(authToken);
            return true;
        } catch (SignatureException e) {
            logger.error("Invalid JWT signature: {}", e.getMessage());
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

// src/main/java/com/example/auth/security/jwt/AuthTokenFilter.java
package com.example.auth.security.jwt;

import com.example.auth.security.services.UserDetailsServiceImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class AuthTokenFilter extends OncePerRequestFilter {
    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    private static final Logger logger = LoggerFactory.getLogger(AuthTokenFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        try {
            String jwt = parseJwt(request);
            if (jwt != null && jwtUtils.validateJwtToken(jwt)) {
                String username = jwtUtils.getUserNameFromJwtToken(jwt);

                UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities());
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        } catch (Exception e) {
            logger.error("Impossible de définir l'authentification utilisateur: {}", e);
        }

        filterChain.doFilter(request, response);
    }

    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader("Authorization");

        if (StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer ")) {
            return headerAuth.substring(7);
        }

        return null;
    }
}

// src/main/java/com/example/auth/security/jwt/AuthEntryPointJwt.java
package com.example.auth.security.jwt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class AuthEntryPointJwt implements AuthenticationEntryPoint {

    private static final Logger logger = LoggerFactory.getLogger(AuthEntryPointJwt.class);

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException authException) throws IOException, ServletException {
        logger.error("Erreur non autorisée: {}", authException.getMessage());
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Erreur: Non autorisé");
    }
}

// 9. Créez le UserDetails service
// src/main/java/com/example/auth/security/services/UserDetailsServiceImpl.java
package com.example.auth.security.services;

import com.example.auth.model.User;
import com.example.auth.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {
    @Autowired
    UserRepository userRepository;

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("Utilisateur non trouvé avec le nom d'utilisateur: " + username));

        return UserDetailsImpl.build(user);
    }
}

// src/main/java/com/example/auth/security/services/UserDetailsImpl.java
package com.example.auth.security.services;

import com.example.auth.model.User;
import com.fasterxml.jackson.annotation.JsonIgnore;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Collections;
import java.util.Objects;

public class UserDetailsImpl implements UserDetails {
    private static final long serialVersionUID = 1L;

    private Long id;
    private String username;
    @JsonIgnore
    private String password;
    private boolean mfaEnabled;

    private Collection<? extends GrantedAuthority> authorities;

    public UserDetailsImpl(Long id, String username, String password, boolean mfaEnabled,
                           Collection<? extends GrantedAuthority> authorities) {
        this.id = id;
        this.username = username;
        this.password = password;
        this.mfaEnabled = mfaEnabled;
        this.authorities = authorities;
    }

    public static UserDetailsImpl build(User user) {
        return new UserDetailsImpl(
                user.getId(),
                user.getUsername(),
                user.getPassword(),
                user.isMfaEnabled(),
                Collections.emptyList());
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    public Long getId() {
        return id;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    public boolean isMfaEnabled() {
        return mfaEnabled;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;
        UserDetailsImpl user = (UserDetailsImpl) o;
        return Objects.equals(id, user.id);
    }
}

// 10. Créez le fichier application.properties
// src/main/resources/application.properties
spring.datasource.url=jdbc:mysql://localhost:3306/auth_db?useSSL=false
spring.datasource.username=root
spring.datasource.password=password

spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.MySQL5InnoDBDialect
spring.jpa.hibernate.ddl-auto=update

# App Properties
app.jwtSecret=votreClefSecreteJWTQuiDoitEtreTresLongueEtComplexePourLaSecurite
app.jwtExpirationMs=86400000
```


### Frontend (Angular)

```javascript
// 1. Créez les services d'authentification et de token
// src/app/_services/auth.service.ts
import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable } from 'rxjs';

const AUTH_API = 'http://localhost:8080/api/auth/';

const httpOptions = {
  headers: new HttpHeaders({ 'Content-Type': 'application/json' })
};

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  constructor(private http: HttpClient) { }

  login(username: string, password: string): Observable<any> {
    return this.http.post(AUTH_API + 'signin', {
      username,
      password
    }, httpOptions);
  }

  verifyCode(username: string, code: string): Observable<any> {
    return this.http.post(AUTH_API + 'verify-code', {
      username,
      code
    }, httpOptions);
  }

  enable2FA(username: string): Observable<any> {
    return this.http.post(AUTH_API + 'enable-2fa', username, httpOptions);
  }

  disable2FA(username: string): Observable<any> {
    return this.http.post(AUTH_API + 'disable-2fa', username, httpOptions);
  }

  register(username: string, password: string): Observable<any> {
    return this.http.post(AUTH_API + 'signup', {
      username,
      password
    }, httpOptions);
  }
}

// src/app/_services/token-storage.service.ts
import { Injectable } from '@angular/core';

const TOKEN_KEY = 'auth-token';
const USER_KEY = 'auth-user';

@Injectable({
  providedIn: 'root'
})
export class TokenStorageService {
  constructor() { }

  signOut(): void {
    window.sessionStorage.clear();
  }

  public saveToken(token: string): void {
    window.sessionStorage.removeItem(TOKEN_KEY);
    window.sessionStorage.setItem(TOKEN_KEY, token);
  }

  public getToken(): string | null {
    return window.sessionStorage.getItem(TOKEN_KEY);
  }

  public saveUser(user: any): void {
    window.sessionStorage.removeItem(USER_KEY);
    window.sessionStorage.setItem(USER_KEY, JSON.stringify(user));
  }

  public getUser(): any {
    const user = window.sessionStorage.getItem(USER_KEY);
    if (user) {
      return JSON.parse(user);
    }

    return {};
  }
}

// 2. Créez l'intercepteur de requêtes HTTP pour les tokens JWT
// src/app/_helpers/auth.interceptor.ts
import { HTTP_INTERCEPTORS, HttpEvent } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { HttpInterceptor, HttpHandler, HttpRequest } from '@angular/common/http';

```

### Exemple de formulaire d'authentification 

```javascript

// 1. Composant de barre de navigation avec menu d'authentification
// src/app/components/nav-menu/nav-menu.component.ts
import { Component, OnInit } from '@angular/core';
import { TokenStorageService } from '../../_services/token-storage.service';

@Component({
  selector: 'app-nav-menu',
  templateUrl: './nav-menu.component.html',
  styleUrls: ['./nav-menu.component.scss']
})
export class NavMenuComponent implements OnInit {
  isLoggedIn = false;
  username?: string;
  isMenuCollapsed = true;

  constructor(private tokenStorage: TokenStorageService) { }

  ngOnInit(): void {
    this.isLoggedIn = !!this.tokenStorage.getToken();

    if (this.isLoggedIn) {
      const user = this.tokenStorage.getUser();
      this.username = user.username;
    }
  }

  logout(): void {
    this.tokenStorage.signOut();
    window.location.reload();
  }

  toggleMenu(): void {
    this.isMenuCollapsed = !this.isMenuCollapsed;
  }
}

// src/app/components/nav-menu/nav-menu.component.html
<nav class="navbar navbar-expand-lg navbar-dark bg-primary">
  <div class="container">
    <a class="navbar-brand" href="#">Mon Application</a>
    <button class="navbar-toggler" type="button" (click)="toggleMenu()">
      <span class="navbar-toggler-icon"></span>
    </button>

    <div class="collapse navbar-collapse" [ngClass]="{'show': !isMenuCollapsed}">
      <ul class="navbar-nav me-auto">
        <li class="nav-item">
          <a class="nav-link" routerLink="/home" routerLinkActive="active">Accueil</a>
        </li>
        <li class="nav-item" *ngIf="isLoggedIn">
          <a class="nav-link" routerLink="/profile" routerLinkActive="active">Profil</a>
        </li>
        <li class="nav-item" *ngIf="isLoggedIn">
          <a class="nav-link" routerLink="/dashboard" routerLinkActive="active">Tableau de bord</a>
        </li>
      </ul>

      <ul class="navbar-nav ml-auto" *ngIf="!isLoggedIn">
        <li class="nav-item">
          <a class="nav-link" routerLink="/login" routerLinkActive="active">Se connecter</a>
        </li>
        <li class="nav-item">
          <a class="nav-link" routerLink="/register" routerLinkActive="active">S'inscrire</a>
        </li>
      </ul>

      <ul class="navbar-nav ml-auto" *ngIf="isLoggedIn">
        <li class="nav-item dropdown">
          <a class="nav-link dropdown-toggle" href="#" id="navbarDropdown" role="button" data-bs-toggle="dropdown" aria-expanded="false">
            {{ username }}
          </a>
          <ul class="dropdown-menu dropdown-menu-end" aria-labelledby="navbarDropdown">
            <li><a class="dropdown-item" routerLink="/profile">Profil</a></li>
            <li><a class="dropdown-item" routerLink="/settings">Paramètres</a></li>
            <li><a class="dropdown-item" routerLink="/security">Sécurité</a></li>
            <li><hr class="dropdown-divider"></li>
            <li><a class="dropdown-item" (click)="logout()" style="cursor: pointer;">Se déconnecter</a></li>
          </ul>
        </li>
      </ul>
    </div>
  </div>
</nav>

// 2. Composant de formulaire de connexion
// src/app/components/login/login.component.ts
import { Component, OnInit } from '@angular/core';
import { AuthService } from '../../_services/auth.service';
import { TokenStorageService } from '../../_services/token-storage.service';
import { Router } from '@angular/router';

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.scss']
})
export class LoginComponent implements OnInit {
  form: any = {
    username: null,
    password: null
  };
  isLoggedIn = false;
  isLoginFailed = false;
  errorMessage = '';
  require2FA = false;
  qrCodeImage = '';
  showQRCode = false;
  totpCode = '';

  constructor(
    private authService: AuthService,
    private tokenStorage: TokenStorageService,
    private router: Router
  ) { }

  ngOnInit(): void {
    if (this.tokenStorage.getToken()) {
      this.isLoggedIn = true;
      this.router.navigate(['/profile']);
    }
  }

  onSubmit(): void {
    const { username, password } = this.form;

    this.authService.login(username, password).subscribe(
      data => {
        if (data.token) {
          // Connexion normale sans 2FA
          this.tokenStorage.saveToken(data.token);
          this.tokenStorage.saveUser(data);
          this.isLoginFailed = false;
          this.isLoggedIn = true;
          this.router.navigate(['/profile']);
        } else if (data.mfaEnabled) {
          // 2FA est requis
          this.require2FA = true;
          this.tokenStorage.saveUser(data);
        }
      },
      err => {
        this.errorMessage = err.error.message;
        this.isLoginFailed = true;
      }
    );
  }

  onVerifyCode(): void {
    this.authService.verifyCode(this.form.username, this.totpCode).subscribe(
      data => {
        this.tokenStorage.saveToken(data.token);
        this.tokenStorage.saveUser(data);
        this.isLoginFailed = false;
        this.isLoggedIn = true;
        this.router.navigate(['/profile']);
      },
      err => {
        this.errorMessage = 'Code invalide. Veuillez réessayer.';
        this.isLoginFailed = true;
      }
    );
  }

  enable2FA(): void {
    this.authService.enable2FA(this.form.username).subscribe(
      data => {
        this.qrCodeImage = data.qrCodeImage;
        this.showQRCode = true;
      },
      err => {
        this.errorMessage = err.error.message;
      }
    );
  }

  reloadPage(): void {
    window.location.reload();
  }
}

// src/app/components/login/login.component.html
<div class="container mt-5">
  <div class="row justify-content-center">
    <div class="col-md-6">
      <div class="card">
        <div class="card-header bg-primary text-white">
          <h4 class="mb-0">Connexion</h4>
        </div>
        <div class="card-body">
          <form *ngIf="!isLoggedIn && !require2FA && !showQRCode" name="form" (ngSubmit)="f.form.valid && onSubmit()" #f="ngForm" novalidate>
            <div class="mb-3">
              <label for="username" class="form-label">Nom d'utilisateur</label>
              <input
                type="text"
                class="form-control"
                id="username"
                name="username"
                [(ngModel)]="form.username"
                required
                #username="ngModel"
                [ngClass]="{ 'is-invalid': f.submitted && username.errors }"
              />
              <div class="invalid-feedback" *ngIf="username.errors && f.submitted">
                Le nom d'utilisateur est requis
              </div>
            </div>
            <div class="mb-3">
              <label for="password" class="form-label">Mot de passe</label>
              <input
                type="password"
                class="form-control"
                id="password"
                name="password"
                [(ngModel)]="form.password"
                required
                minlength="6"
                #password="ngModel"
                [ngClass]="{ 'is-invalid': f.submitted && password.errors }"
              />
              <div class="invalid-feedback" *ngIf="password.errors && f.submitted">
                <div *ngIf="password.errors['required']">Le mot de passe est requis</div>
                <div *ngIf="password.errors['minlength']">
                  Le mot de passe doit contenir au moins 6 caractères
                </div>
              </div>
            </div>
            <div class="mb-3 form-check">
              <input type="checkbox" class="form-check-input" id="remember">
              <label class="form-check-label" for="remember">Se souvenir de moi</label>
            </div>
            <div class="d-grid">
              <button class="btn btn-primary">
                Se connecter
              </button>
            </div>
          </form>

          <!-- Formulaire de vérification 2FA -->
          <form *ngIf="require2FA && !showQRCode" name="verify-form" (ngSubmit)="v.form.valid && onVerifyCode()" #v="ngForm" novalidate>
            <div class="alert alert-info" role="alert">
              Une authentification à deux facteurs est requise. Veuillez saisir le code de votre application d'authentification.
            </div>
            <div class="mb-3">
              <label for="totpCode" class="form-label">Code de vérification</label>
              <input
                type="text"
                class="form-control"
                id="totpCode"
                name="totpCode"
                [(ngModel)]="totpCode"
                required
                minlength="6"
                maxlength="6"
                #code="ngModel"
                [ngClass]="{ 'is-invalid': v.submitted && code.errors }"
              />
              <div class="invalid-feedback" *ngIf="code.errors && v.submitted">
                <div *ngIf="code.errors['required']">Le code est requis</div>
                <div *ngIf="code.errors['minlength'] || code.errors['maxlength']">
                  Le code doit contenir 6 chiffres
                </div>
              </div>
            </div>
            <div class="d-grid">
              <button class="btn btn-primary">
                Vérifier
              </button>
            </div>
          </form>

          <!-- Affichage du QR Code -->
          <div *ngIf="showQRCode">
            <div class="alert alert-success" role="alert">
              Scannez ce code QR avec votre application d'authentification (comme Google Authenticator, Microsoft Authenticator ou Authy).
            </div>
            <div class="text-center mb-3">
              <img [src]="qrCodeImage" alt="QR Code pour 2FA" class="img-fluid" />
            </div>
            <div class="d-grid">
              <button class="btn btn-primary" (click)="reloadPage()">
                J'ai scanné le code, continuer
              </button>
            </div>
          </div>

          <div class="alert alert-danger" *ngIf="isLoginFailed">
            Échec de la connexion: {{ errorMessage }}
          </div>
        </div>
        <div class="card-footer">
          <div class="d-flex justify-content-between">
            <a routerLink="/register" class="text-decoration-none">Créer un compte</a>
            <a routerLink="/forgot-password" class="text-decoration-none">Mot de passe oublié?</a>
          </div>
        </div>
      </div>
    </div>
  </div>
</div>

// 3. Composant de page de profil avec gestion de la 2FA
// src/app/components/profile/profile.component.ts
import { Component, OnInit } from '@angular/core';
import { TokenStorageService } from '../../_services/token-storage.service';
import { AuthService } from '../../_services/auth.service';

@Component({
  selector: 'app-profile',
  templateUrl: './profile.component.html',
  styleUrls: ['./profile.component.scss']
})
export class ProfileComponent implements OnInit {
  currentUser: any;
  qrCodeImage = '';
  showQRCode = false;

  constructor(
    private token: TokenStorageService,
    private authService: AuthService
  ) { }

  ngOnInit(): void {
    this.currentUser = this.token.getUser();
  }

  enable2FA(): void {
    this.authService.enable2FA(this.currentUser.username).subscribe(
      data => {
        this.qrCodeImage = data.qrCodeImage;
        this.showQRCode = true;
        this.currentUser.mfaEnabled = true;
        this.token.saveUser(this.currentUser);
      },
      err => {
        console.error(err);
      }
    );
  }

  disable2FA(): void {
    this.authService.disable2FA(this.currentUser.username).subscribe(
      data => {
        this.currentUser.mfaEnabled = false;
        this.token.saveUser(this.currentUser);
      },
      err => {
        console.error(err);
      }
    );
  }
}

// src/app/components/profile/profile.component.html
<div class="container mt-5">
  <div class="row">
    <div class="col-md-4">
      <div class="card">
        <div class="card-header bg-primary text-white">
          <h4 class="mb-0">Profil</h4>
        </div>
        <div class="card-body text-center">
          <img src="https://via.placeholder.com/150" class="rounded-circle img-fluid mb-3" alt="Photo de profil">
          <h4>{{ currentUser.username }}</h4>
          <p class="text-muted">Utilisateur</p>
        </div>
        <ul class="list-group list-group-flush">
          <li class="list-group-item">
            <i class="fas fa-user me-2"></i> Mon profil
          </li>
          <li class="list-group-item">
            <i class="fas fa-cog me-2"></i> Paramètres
          </li>
          <li class="list-group-item active">
            <i class="fas fa-shield-alt me-2"></i> Sécurité
          </li>
          <li class="list-group-item">
            <i class="fas fa-bell me-2"></i> Notifications
          </li>
        </ul>
      </div>
    </div>
    
    <div class="col-md-8">
      <div class="card">
        <div class="card-header bg-primary text-white">
          <h4 class="mb-0">Sécurité du compte</h4>
        </div>
        <div class="card-body">
          <h5>Authentification à deux facteurs (2FA)</h5>
          <p class="text-muted">L'authentification à deux facteurs ajoute une couche de sécurité supplémentaire à votre compte en nécessitant un code temporaire en plus de votre mot de passe lors de la connexion.</p>
          
          <div class="d-flex align-items-center mb-4">
            <div class="me-3">
              <span class="badge" [ngClass]="currentUser.mfaEnabled ? 'bg-success' : 'bg-danger'">
                {{ currentUser.mfaEnabled ? 'Activé' : 'Désactivé' }}
              </span>
            </div>
            <div>
              <button 
                *ngIf="!currentUser.mfaEnabled" 
                class="btn btn-success" 
                (click)="enable2FA()">
                Activer la 2FA
              </button>
              <button 
                *ngIf="currentUser.mfaEnabled" 
                class="btn btn-danger" 
                (click)="disable2FA()">
                Désactiver la 2FA
              </button>
            </div>
          </div>

          <!-- Affichage du QR Code -->
          <div *ngIf="showQRCode" class="qr-code-section">
            <div class="alert alert-info mb-3">
              Scannez ce code QR avec votre application d'authentification (comme Google Authenticator, Microsoft Authenticator ou Authy).
            </div>
            <div class="text-center mb-3">
              <img [src]="qrCodeImage" alt="QR Code pour 2FA" class="img-fluid" />
            </div>
            <div class="alert alert-warning">
              <strong>Important:</strong> Conservez une copie des codes de récupération qui vous seront fournis. Si vous perdez l'accès à votre application d'authentification, ces codes seront le seul moyen de récupérer votre compte.
            </div>
          </div>

          <hr>

          <h5>Mot de passe</h5>
          <p class="text-muted">Il est recommandé de changer régulièrement votre mot de passe et d'utiliser un mot de passe fort unique pour chaque site.</p>
          <button class="btn btn-outline-primary">Changer le mot de passe</button>

          <hr>

          <h5>Sessions actives</h5>
          <p class="text-muted">Voici les appareils actuellement connectés à votre compte.</p>
          
          <div class="card mb-2">
            <div class="card-body">
              <div class="d-flex justify-content-between align-items-center">
                <div>
                  <h6 class="mb-0">Cet appareil</h6>
                  <small class="text-muted">Dernière activité: Maintenant</small>
                </div>
                <button class="btn btn-sm btn-outline-danger">Déconnecter</button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</div>

// 4. Composant d'inscription
// src/app/components/register/register.component.ts
import { Component, OnInit } from '@angular/core';
import { AuthService } from '../../_services/auth.service';
import { Router } from '@angular/router';

@Component({
  selector: 'app-register',
  templateUrl: './register.component.html',
  styleUrls: ['./register.component.scss']
})
export class RegisterComponent implements OnInit {
  form: any = {
    username: null,
    password: null
  };
  isSuccessful = false;
  isSignUpFailed = false;
  errorMessage = '';

  constructor(private authService: AuthService, private router: Router) { }

  ngOnInit(): void {
  }

  onSubmit(): void {
    const { username, password } = this.form;

    this.authService.register(username, password).subscribe(
      data => {
        this.isSuccessful = true;
        this.isSignUpFailed = false;
        setTimeout(() => {
          this.router.navigate(['/login']);
        }, 3000);
      },
      err => {
        this.errorMessage = err.error.message;
        this.isSignUpFailed = true;
      }
    );
  }
}

// src/app/components/register/register.component.html
<div class="container mt-5">
  <div class="row justify-content-center">
    <div class="col-md-6">
      <div class="card">
        <div class="card-header bg-primary text-white">
          <h4 class="mb-0">Inscription</h4>
        </div>
        <div class="card-body">
          <form
            *ngIf="!isSuccessful"
            name="form"
            (ngSubmit)="f.form.valid && onSubmit()"
            #f="ngForm"
            novalidate
          >
            <div class="mb-3">
              <label for="username" class="form-label">Nom d'utilisateur</label>
              <input
                type="text"
                class="form-control"
                id="username"
                name="username"
                [(ngModel)]="form.username"
                required
                minlength="3"
                maxlength="20"
                #username="ngModel"
                [ngClass]="{ 'is-invalid': f.submitted && username.errors }"
              />
              <div class="invalid-feedback" *ngIf="username.errors && f.submitted">
                <div *ngIf="username.errors['required']">Le nom d'utilisateur est requis</div>
                <div *ngIf="username.errors['minlength']">
                  Le nom d'utilisateur doit contenir au moins 3 caractères
                </div>
                <div *ngIf="username.errors['maxlength']">
                  Le nom d'utilisateur ne doit pas dépasser 20 caractères
                </div>
              </div>
            </div>
            <div class="mb-3">
              <label for="password" class="form-label">Mot de passe</label>
              <input
                type="password"
                class="form-control"
                id="password"
                name="password"
                [(ngModel)]="form.password"
                required
                minlength="6"
                #password="ngModel"
                [ngClass]="{ 'is-invalid': f.submitted && password.errors }"
              />
              <div class="invalid-feedback" *ngIf="password.errors && f.submitted">
                <div *ngIf="password.errors['required']">Le mot de passe est requis</div>
                <div *ngIf="password.errors['minlength']">
                  Le mot de passe doit contenir au moins 6 caractères
                </div>
              </div>
            </div>
            <div class="mb-3">
              <label for="confirmPassword" class="form-label">Confirmer le mot de passe</label>
              <input
                type="password"
                class="form-control"
                id="confirmPassword"
                name="confirmPassword"
                [(ngModel)]="form.confirmPassword"
                required
                #confirmPassword="ngModel"
                [ngClass]="{ 'is-invalid': f.submitted && confirmPassword.errors }"
              />
              <div class="invalid-feedback" *ngIf="confirmPassword.errors && f.submitted">
                <div *ngIf="confirmPassword.errors['required']">La confirmation du mot de passe est requise</div>
                <div *ngIf="form.confirmPassword !== form.password">
                  Les mots de passe ne correspondent pas
                </div>
              </div>
            </div>
            <div class="mb-3 form-check">
              <input
                type="checkbox"
                class="form-check-input"
                id="terms"
                name="terms"
                [(ngModel)]="form.terms"
                required
                #terms="ngModel"
                [ngClass]="{ 'is-invalid': f.submitted && terms.errors }"
              />
              <label class="form-check-label" for="terms">
                J'accepte les <a href="#">termes et conditions</a>
              </label>
              <div class="invalid-feedback" *ngIf="terms.errors && f.submitted">
                Vous devez accepter les termes et conditions
              </div>
            </div>
            <div class="d-grid">
              <button class="btn btn-primary">S'inscrire</button>
            </div>
          </form>

          <div class="alert alert-success" *ngIf="isSuccessful">
            Inscription réussie! Vous allez être redirigé vers la page de connexion...
          </div>

          <div class="alert alert-danger" *ngIf="isSignUpFailed">
            Échec de l'inscription: {{ errorMessage }}
          </div>
        </div>
        <div class="card-footer text-center">
          <p class="mb-0">Vous avez déjà un compte? <a routerLink="/login">Se connecter</a></p>
        </div>
      </div>
    </div>
  </div>
</div>

// 5. Composant de garde d'authentification
// src/app/_helpers/auth.guard.ts
import { Injectable } from '@angular/core';
import { Router, CanActivate, ActivatedRouteSnapshot, RouterStateSnapshot } from '@angular/router';
import { TokenStorageService } from '../_services/token-storage.service';

@Injectable({ providedIn: 'root' })
export class AuthGuard implements CanActivate {
    constructor(
        private router: Router,
        private tokenStorage: TokenStorageService
    ) { }

    canActivate(route: ActivatedRouteSnapshot, state: RouterStateSnapshot) {
        const token = this.tokenStorage.getToken();
        if (token) {
            // Utilisateur connecté
            return true;
        }

        // L'utilisateur n'est pas connecté, redirection vers la page de connexion
        this.router.navigate(['/login'], { queryParams: { returnUrl: state.url } });
        return false;
    }
}

// 6. Module principal de l'application
// src/app/app.module.ts
import { NgModule } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';
import { FormsModule } from '@angular/forms';
import { HttpClientModule } from '@angular/common/http';

import { AppRoutingModule } from './app-routing.module';
import { AppComponent } from './app.component';
import { LoginComponent } from './components/login/login.component';
import { RegisterComponent } from './components/register/register.component';
import { NavMenuComponent } from './components/nav-menu/nav-menu.component';
import { ProfileComponent } from './components/profile/profile.component';

import { authInterceptorProviders } from './_helpers/auth.interceptor';

@NgModule({
  declarations: [
    AppComponent,
    LoginComponent,
    RegisterComponent,
    NavMenuComponent,
    ProfileComponent
  ],
  imports: [
    BrowserModule,
    AppRoutingModule,
    FormsModule,
    HttpClientModule
  ],
  providers: [authInterceptorProviders],
  bootstrap: [AppComponent]
})
export class AppModule { }

// 7. Configuration des routes
// src/app/app-routing.module.ts
import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';

import { LoginComponent } from './components/login/login.component';
import { RegisterComponent } from './components/register/register.component';
import { ProfileComponent } from './components/profile/profile.component';
import { AuthGuard } from './_helpers/auth.guard';

const routes: Routes = [
  { path: 'login', component: LoginComponent },
  { path: 'register', component: RegisterComponent },
  { path: 'profile', component: ProfileComponent, canActivate: [AuthGuard] },
  { path: '', redirectTo: 'login', pathMatch: 'full' }
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule { }

// 8. Composant principal de l'application
// src/app/app.component.ts
import { Component, OnInit } from '@angular/core';
import { TokenStorageService } from './_services/token-storage.service';

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.scss']
})
export class AppComponent implements OnInit {
  title = 'angular-2fa-app';

  constructor(private tokenStorageService: TokenStorageService) { }

  ngOnInit(): void {
  }
}

// src/app/app.component.html
<app-nav-menu></app-nav-menu>
<router-outlet></router-outlet>

// 9. Styles globaux
// src/styles.scss
/* Vous pouvez importer Bootstrap ici */
@import '~bootstrap/dist/css/bootstrap.min.css';
@import '~@fortawesome/fontawesome-free/css/all.min.css';

body {
  background-color: #f8f9fa;
  padding-bottom: 50px;
}

.card {
  box-shadow: 0 0.5rem 1rem rgba(0, 0, 0, 0.15);
  border: none;
}

.card-header {
  border-bottom: none;
}

.btn-primary {
  background-color: #007bff;
}

.btn-primary:hover {
  background-color: #0069d9;
}

```