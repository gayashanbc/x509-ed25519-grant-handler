# Ed25519 Grant Handler
This grant handler allows users to obtain OAuth tokens from WSO2 Identity by exchanging an SSH certificate of type ssh-ed25519-cert-v01@openssh.com.

## Installing
### Building from source
1. Clone the repository with `git clone https://github.com/gayashanbc/x509-ed25519-grant-handler.git`.
2. Build using Maven `mvn clean install`.

You can find the `wso2is-identity-samples-oauth2-ssh-ed25519-cert-v01-grant-1.0.0.jar` inside the `target` folder of the project root directory.

### Downloading the release artifact
1. Download [wso2is-identity-samples-oauth2-ssh-ed25519-cert-v01-grant-1.0.0.jar](https://github.com/gayashanbc/x509-ed25519-grant-handler/releases/download/1.0.0/wso2is-identity-samples-oauth2-ssh-ed25519-cert-v01-grant-1.0.0.jar).

## Configuring
1. Copy `wso2is-identity-samples-oauth2-ssh-ed25519-cert-v01-grant-1.0.0.jar` to `<IS_HOME>/repository/components/dropins` directory.
2. Append the following configuration to `deployment.toml` file located in `<IS_HOME>/repository/conf`.

```toml
[[oauth.custom_grant_type]]
name="x509"
grant_handler="org.wso2.sample.identity.oauth2.grant.ed25519.X509GrantHandler"
grant_validator="org.wso2.sample.identity.oauth2.grant.ed25519.X509GrantValidator"
[oauth.custom_grant_type.properties]
IdTokenAllowed=true
```
3. Restart WSO2 IS.
4. Configure a service provider to test the sample under OpenId connect configurations.
5. You will be able to see "x509" as a grant type under supported grant types and enable it.
6. Click update on service provider configurations.
7. Once the service provider is saved, you will be redirected to the `Service Provider Details` page. Here, expand the
    `Inbound Authentication Configuration` section and click the `OAuth/OpenID Connect Configuration` section. Copy the
    values of  `OAuth Client Key` and `OAuth Client Secret` shown here.
    ![OAuth Client Credentials](https://user-images.githubusercontent.com/15249242/91567068-27155e00-e962-11ea-8eab-b3bdd790bfd4.png)

### Trying out
Executing the following sample cURL request to try out the grant handler after replacing `<OAuth Client Key>` and `<OAuth Client Secret>` with the respective values.<br/>
Note that the user principal presented in the certificate: `test_user` needs to exist in a user store for the request to be completed successfully.
```shell script
curl -kv \ 
 --data-urlencode "grant_type=x509" \
 --data-urlencode "scope=openid" \
 --data-urlencode "x509=ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIL+dMYrVu2I49m5CqY/RkPiDwYppvsGAB0LiNHB/2BD9AAAAIGMKpNu2xYZk1gLzuEPHQTbnlz6RYvvvo3U9ygPOzOC0DeC2s6dj//8AAAABAAAAEHNvbWVfdXNlcl9rZXlfaWQAAAANAAAACXRlc3RfdXNlcgAAAABflxx0AAAAAF+XKtgAAAAAAAAAggAAABVwZXJtaXQtWDExLWZvcndhcmRpbmcAAAAAAAAAF3Blcm1pdC1hZ2VudC1mb3J3YXJkaW5nAAAAAAAAABZwZXJtaXQtcG9ydC1mb3J3YXJkaW5nAAAAAAAAAApwZXJtaXQtcHR5AAAAAAAAAA5wZXJtaXQtdXNlci1yYwAAAAAAAAAAAAAAMwAAAAtzc2gtZWQyNTUxOQAAACBb6BeFLgueUbj6eAwxZ/ajSRTf0NTcbjxfhfmGMluBhwAAAFMAAAALc3NoLWVkMjU1MTkAAABAawGKwVXXAWaFTi9KO4HgZOLq8LcmUuDvb3ScqySBUz+O6euwVWqXu0by8uS66sJnU/1uOzsIs/ZekaaMum/+Dw== user@host" \
 https://localhost:9443/oauth2/token \
 -u <OAuth Client Key>:<OAuth Client Secret>
```

## Debugging
Append the following configurations to `loggers` section of the `log4j2.properties` file located in `<IS_HOME>/repository/conf`

```
logger.org-wso2-sample-identity-oauth2-grant-ed25519.name=org.wso2.sample.identity.oauth2.grant.ed25519
logger.org-wso2-sample-identity-oauth2-grant-ed25519.level=DEBUG
```
