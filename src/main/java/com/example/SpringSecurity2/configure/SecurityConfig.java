package com.example.SpringSecurity2.configure;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@Configuration

public class SecurityConfig {
  @Bean

  //cargar un usuario de autenticacion en memoria (no en base de datos)

  protected UserDetailsService userDetailsService()  throws Exception {
    UserDetailsManager userDetailsManager = new InMemoryUserDetailsManager();
    UserDetails user = User.withUsername("abby")
        .password(passwordEncoder().encode("12345"))
        .authorities("read") .build();
    userDetailsManager.createUser(user);
    return userDetailsManager;


  }

  //se una la intancia de BCryptPasswordEncoder para codificar la contaseña de el usuario de ejemplo

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }
  @Bean
  //Configuración de seguridad HTTP


  protected SecurityFilterChain configure(HttpSecurity http) throws Exception {
    //para deshabilitar  el crf
    http.csrf().disable()
        //para exigir que todas las requests sean autorizadas
        .authorizeRequests().anyRequest().authenticated()
        .and()
        .formLogin()
        .and()
        .rememberMe()
        .and() .logout() .logoutUrl("/logout")
        .logoutSuccessUrl("/login") .deleteCookies("remember-me");

    return http.build();
  }
}