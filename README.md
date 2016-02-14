
# Описание

## Запуск

```bash
$> spring run authorization.groovy -- --spring.profiles.active=authorization &
$> spring run service.groovy -- --spring.profiles.active=service &
$> spring run zuul.groovy -- --spring.profiles.active=zuul &
```

Проверка работы, авторизация пользователем:

```bash
$> curl "http://localhost:9003/login?username=artem&password=artem_password" | jq .access_token
$> export TOKEN=<token_value>
$> curl localhost:9003/service/authorized -H "Authorization: Bearer $TOKEN"
Only authorized clients see this
$> curl localhost:9003/service/inner -H "Authorization: Bearer $TOKEN"
Only authorized clients with inner scope see this
$> curl localhost:9003/service/public -H "Authorization: Bearer $TOKEN"
Only authorized clients with public scope see this
$> curl localhost:9003/service/user -H "Authorization: Bearer $TOKEN"
Only clients with role USER see this
$> curl localhost:9003/service/admin -H "Authorization: Bearer $TOKEN"
{"error":"access_denied","error_description":"Access is denied"}
```

Проверка работы, авторизация приложением:

```bash
$> curl -v artem:artem_password@localhost:9003/uaa/oauth/authorize \
     -d response_type=token \
     -d client_id=third_party_app \
     -d redirect_uri=http://example.com \
     -d scope=public_scope \
     -d state=3213
$> export TOKEN=<token_value>
$> curl localhost:9003/service/authorized -H "Authorization: Bearer $TOKEN"
Only authorized clients see this
$> curl localhost:9003/service/inner -H "Authorization: Bearer $TOKEN"
{"error":"access_denied","error_description":"Access is denied"}
$> curl localhost:9003/service/public -H "Authorization: Bearer $TOKEN"
Only authorized clients with public scope see this
$> curl localhost:9003/service/user -H "Authorization: Bearer $TOKEN"
Only clients with role USER see this
$> curl localhost:9003/service/admin -H "Authorization: Bearer $TOKEN"
{"error":"access_denied","error_description":"Access is denied"}
```

## [Сервис Авторизации](https://github.com/xxlabaza/groovy-auth2-sample/blob/master/authorization.groovy)

### Пользователи

Список пользователей и их роли с паролями в сервисе захардкожены, в классе **GlobalAuthenticationConfiguration**:

```java
authenticationManagerBuilder.inMemoryAuthentication()
            .withUser('artem')
            .password('artem_password')
            .roles('USER')
        .and()
            .withUser('admin')
            .password('admin')
            .roles('ADMIN')
```

Для того, что бы загружать пользователей из стороннего сервиса, необходимо реализовать свою имплементацию абстрактного класса [AbstractUserDetailsAuthenticationProvider](http://docs.spring.io/spring-security/site/docs/4.0.3.RELEASE/apidocs//org/springframework/security/authentication/dao/AbstractUserDetailsAuthenticationProvider.html) и использовать его так:

```java
authenticationManagerBuilder
        .authenticationProvider(<my_implementation>)
```

### JWT

Приватный и публичный **JWT**-ключи указаны в настройках [application.yml](https://github.com/xxlabaza/groovy-auth2-sample/blob/master/application.yml) в явном виде, но что бы хранить их болле надёжно - необходимо создать [keystore](http://docs.oracle.com/cd/E23943_01/core.1111/e10105/wallets.htm#ASADM2021).

Создаём **keystore**:

```bash
keytool -genkeypair \
  -alias keystore_alias \
  -keyalg RSA \
  -dname "CN=Artem Labazin,OU=jwt,O=ArtLab,L=SPb,S=SPb,C=RU" \
  -keypass ArtLab90 \
  -keystore keystore.jks \
  -storepass ArtLab90
```

Получаем публичный ключ:

```bash
keytool -list -rfc --keystore keystore.jks | openssl x509 -inform pem -pubkey
```

Так же необходимо заменить настройки **jwtAccessTokenConverter**:

```java
@Bean
JwtAccessTokenConverter jwtAccessTokenConverter () {
    def converter = new JwtAccessTokenConverter()
    def keyPair = new KeyStoreKeyFactory(
            new ClassPathResource('keystore.jks'),
            'ArtLab90'.toCharArray()
    ).getKeyPair('keystore_alias')
    converter.setKeyPair(keyPair)
}
```

### Хранение токенов

Для того, что бы не хранить информацию о генерируемых токенах и сервисах-клиентах в памяти, а хранить их в БД, необходимо произвести следующие настройки:

Заменить **tokenStore**:

```java
@Bean
TokenStore tokenStore () {
    new JdbcTokenStore(dataSource)
}
```

Создать **clientDetailsService**:

```java
@Bean
ClientDetailsService clientDetailsService () {
    def clientDetailsService = new JdbcClientDetailsService(dataSource)
    clientDetailsService.setPasswordEncoder(passwordEncoder())
    return clientDetailsService
}

@Bean
PasswordEncoder passwordEncoder () {
    new BCryptPasswordEncoder(10)
}
```

Перенастроить **clientDetailsService**:

```java
@Override
void configure (ClientDetailsServiceConfigurer clients) throws Exception {
    clients.withClientDetails(clientDetailsService())
}
```

## [Ресурс сервис](https://github.com/xxlabaza/groovy-auth2-sample/blob/master/service.groovy)

## [Шлюз](https://github.com/xxlabaza/groovy-auth2-sample/blob/master/zuul.groovy)

## Полезные ссылки

* [Как работает JWT](http://jwt.io/introduction/)

* [Работа с social](https://spring.io/guides/tutorials/spring-boot-oauth2/)

* [Описание работы с oAuth2](http://callistaenterprise.se/blogg/teknik/2015/04/27/building-microservices-part-3-secure-APIs-with-OAuth/)

* [Пример проекта с oAuth2](https://github.com/dynamind/spring-boot-security-oauth2-minimal)

