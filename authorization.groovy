@Grab('spring-security-jwt')

import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.authentication.configurers.GlobalAuthenticationConfigurerAdapter
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer
import org.springframework.security.oauth2.provider.token.TokenStore
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory

@Configuration
@EnableResourceServer
class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {

    @Value('${my_config.privateKey}')
    String privateKey

    @Value('${my_config.privateKey}')
    String publicKey

    @Autowired
    AuthenticationManager authenticationManager

    @Override
    void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints
                .authenticationManager(authenticationManager)
                .accessTokenConverter(jwtAccessTokenConverter())
                .tokenStore(tokenStore())
    }

    // Defines the security constraints on the token endpoints /oauth/token_key and /oauth/check_token
    @Override
    void configure (AuthorizationServerSecurityConfigurer security) throws Exception {
        security
                .tokenKeyAccess("permitAll()")
                .checkTokenAccess("isAuthenticated()")
    }

    @Override
    void configure (ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory()
                    .withClient('zuul')
                    .secret('zuul_password')
                    .authorizedGrantTypes('refresh_token', 'password')
                    .scopes('inner_scope', 'public_scope')
                .and()
                    .withClient('third_party_app')
                    .secret('third_party_app_password')
                    .authorizedGrantTypes('authorization_code', 'implicit')
                    .scopes('public_scope')
                    .autoApprove(true)
    }

    @Bean
    JwtAccessTokenConverter jwtAccessTokenConverter () {
        def converter = new JwtAccessTokenConverter();
        converter.setSigningKey(privateKey);
        converter.setVerifierKey(publicKey);
        return converter
    }

    @Bean
    TokenStore tokenStore () {
        new InMemoryTokenStore()
    }
}

@Configuration
@EnableAuthorizationServer
class GlobalAuthenticationConfiguration extends GlobalAuthenticationConfigurerAdapter {

    @Autowired
    void init (AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
        authenticationManagerBuilder.inMemoryAuthentication()
                    .withUser('artem')
                    .password('artem_password')
                    .roles('USER')
                .and()
                    .withUser('admin')
                    .password('admin')
                    .roles('ADMIN')
    }
}
