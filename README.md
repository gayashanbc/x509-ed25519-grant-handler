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
1. Coyy `wso2is-identity-samples-oauth2-ssh-ed25519-cert-v01-grant-1.0.0.jar` to `<IS_HOME>/repository/components/dropins` directory.
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

## Debugging
Append the following configurations to `log4j2.properties` file located in `<IS_HOME>/repository/conf`

```
logger.org-wso2-sample-identity-oauth2-grant-ed25519.name=org.wso2.sample.identity.oauth2.grant.ed25519
logger.org-wso2-sample-identity-oauth2-grant-ed25519.level=DEBUG
```
