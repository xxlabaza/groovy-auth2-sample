
@Grab('spring-security-jwt')

import org.springframework.security.access.annotation.Secured


@Configuration
@EnableResourceServer
@EnableGlobalMethodSecurity(
        securedEnabled = true,
        prePostEnabled = true
)
class SecurityConfiguration {

}

@RestController
class Application {

    @RequestMapping('/authorized')
    def authorized () {
        'Only authorized clients see this'
    }

    @PreAuthorize("#oauth2.hasScope('inner_scope')")
    @RequestMapping('/inner')
    def innerScope () {
        'Only authorized clients with inner scope see this'
    }

    @PreAuthorize("#oauth2.hasScope('public_scope')")
    @RequestMapping('/public')
    def publicScope () {
        'Only authorized clients with public scope see this'
    }

    @Secured('ROLE_USER')
    @RequestMapping('/user')
    def user () {
        'Only clients with role USER see this'
    }

    @Secured('ROLE_ADMIN')
    @RequestMapping('/admin')
    def admin () {
        'Only clients with role ADMIN see this'
    }
}