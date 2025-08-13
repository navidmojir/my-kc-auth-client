

1- Dependency:
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
    </dependency>
    <dependency>
        <groupId>ir.mojir</groupId>
		<artifactId>my-kc-auth-client</artifactId>
		<version>0.0.1-SNAPSHOT</version>
    </dependency>

2- application.properties:
spring.security.oauth2.resourceserver.jwt.issuer-uri=http://localhost:8080/realms/cbi

3-
@Configuration
public class SecurityConfig {

	@Autowired
	private KeycloakAuthorizationSecurityFilter keycloakAuthorizationSecurityFilter;
	
	@Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
            .authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated())
            .oauth2ResourceServer((oauth) -> oauth.jwt(Customizer.withDefaults()))
            .addFilterAfter(keycloakAuthorizationSecurityFilter, AuthorizationFilter.class)
            .build();
    
    }
}

4- kc config:

kc.realm=cbi
kc.authServerUrl=http://localhost:8080
kc.clientId=demo
kc.clientSecret=

5- compoment scan
	@ComponentScan(basePackages = "com.example.demo, ir.mojir.my_kc_auth_client")