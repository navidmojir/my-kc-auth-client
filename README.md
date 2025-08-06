

1- Dependency:
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
    </dependency>

2- application.properties:
spring.security.oauth2.resourceserver.jwt.issuer-uri=http://localhost:8080

3-
@Configuration
public class SecurityConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
            .authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated())
            .oauth2ResourceServer((oauth) -> oauth.jwt(Customizer.withDefaults()))
            .build();
    
    }
}