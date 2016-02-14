@Grab('org.springframework.cloud:spring-cloud-starter-zuul:1.0.6.RELEASE')
@Grab('org.springframework.security.oauth:spring-security-oauth2:2.0.7.RELEASE')

import org.springframework.cloud.netflix.zuul.EnableZuulProxy
import org.springframework.boot.autoconfigure.security.oauth2.OAuth2ClientProperties
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordResourceDetails
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordAccessTokenProvider
import org.springframework.security.oauth2.client.OAuth2RestTemplate

@EnableZuulProxy
class Zuul {

}

@RestController
class PasswordLoginController {

    @Value('${security.oauth2.client.accessTokenUri}')
    String accessTokenUri

    @Value('${security.oauth2.client.scope}')
    String scope

    @Autowired
    OAuth2ClientProperties oAuth2ClientProperties

    @RequestMapping('/login')
    def login (@RequestParam('username') String username,
               @RequestParam('password') String password
    ) {
        def resourceDetails = new ResourceOwnerPasswordResourceDetails()
        resourceDetails.username = username
        resourceDetails.password = password
        resourceDetails.accessTokenUri = accessTokenUri
        resourceDetails.clientId = oAuth2ClientProperties.clientId
        resourceDetails.clientSecret = oAuth2ClientProperties.clientSecret
        resourceDetails.scope = scope.split(',')

        def template = new OAuth2RestTemplate(resourceDetails)
        template.accessTokenProvider = new ResourceOwnerPasswordAccessTokenProvider()

        return template.getAccessToken()
    }
}
