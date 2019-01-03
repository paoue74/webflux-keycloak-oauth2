package com.sweepit.keycloakoauth2;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverterAdapter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;


@SpringBootApplication
public class KeycloakOauth2Application {

  public static void main(String[] args) {
    SpringApplication.run(KeycloakOauth2Application.class, args);
  }

}

@Slf4j
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
class SecurityConfig {

  @Bean
  SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
    http
        .csrf().disable()
        .formLogin().disable()
        .httpBasic().disable()
        .authorizeExchange()
        .pathMatchers(HttpMethod.OPTIONS).permitAll()
        .pathMatchers("/user").hasAuthority("USER")
        .pathMatchers("/admin").hasRole("ADMIN")
        .anyExchange().denyAll()
        .and()
        .oauth2ResourceServer()
        .jwt().jwtAuthenticationConverter(grantedAuthoritiesExtractor());
    return http.build();
  }

  private Converter<Jwt, Mono<AbstractAuthenticationToken>> grantedAuthoritiesExtractor() {
    GrantedAuthoritiesExtractor extractor = new GrantedAuthoritiesExtractor();
    return new ReactiveJwtAuthenticationConverterAdapter(extractor);
  }

  static class GrantedAuthoritiesExtractor extends JwtAuthenticationConverter {

    @Override
    protected Collection<GrantedAuthority> extractAuthorities(Jwt jwt) {
      Map<String, Object> claims = jwt.getClaims();
      JSONObject realm_access = (JSONObject) claims.get("realm_access");
      JSONArray roles = (JSONArray) realm_access.get("roles");

      Collection<String> authorities = roles.stream()
          .map(Object::toString)
          .collect(Collectors.toSet());
      return authorities.stream()
          .map(SimpleGrantedAuthority::new)
          .collect(Collectors.toList());
    }
  }
}

class RealmAccess {

  Collection<String> roles = Collections.emptySet();
}

@RestController
class UserController {

  @GetMapping
  Mono<String> greetings() {
    return Mono.just("Thank you !!");
  }

  @GetMapping("/user")
  Mono<String> greetingsFromUser() {
    return Mono.just("Thank you user !!");
  }

  @GetMapping("/admin")
  Mono<String> greetingsFromAdmin() {
    return Mono.just("Thank you admin !!");
  }
}

