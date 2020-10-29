/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.sample.identity.oauth2.grant.ed25519;

import com.hierynomus.sshj.userauth.certificate.Certificate;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AbstractAuthorizationGrantHandler;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.sample.identity.oauth2.grant.ed25519.internal.GrantHandlerServiceComponent;
import org.wso2.sample.identity.oauth2.grant.ed25519.model.sshj.Buffer;
import org.wso2.sample.identity.oauth2.grant.ed25519.model.sshj.KeyType;

import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.util.List;
import java.util.Map;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * ssh-ed25519-cert-v01 grant type for Identity Server
 */
public class X509GrantHandler extends AbstractAuthorizationGrantHandler {

    private static final String SSH_CERT_TYPE_ED25519 = "ssh-ed25519-cert-v01@openssh.com";
    private static final String ACCOUNT_LOCKED_CLAIM = "http://wso2.org/claims/identity/accountLocked";
    private static final String ACCOUNT_DISABLED_CLAIM = "http://wso2.org/claims/identity/accountDisabled";
    private static Log log = LogFactory.getLog(X509GrantHandler.class);
    private static final String X509_GRANT_PARAM = "x509";

    @Override
    public boolean validateGrant(OAuthTokenReqMessageContext oAuthTokenReqMessageContext) throws
            IdentityOAuth2Exception {

        String certificateParameterValue = null;
        String username = null;

        // Extract request parameters.
        RequestParameter[] requestParameters = oAuthTokenReqMessageContext.getOauth2AccessTokenReqDTO()
                .getRequestParameters();

        // Extract 'x509' param from the request.
        for (RequestParameter parameter : requestParameters) {
            if (X509_GRANT_PARAM.equals(parameter.getKey()) && !ArrayUtils.isEmpty(parameter.getValue())) {
                certificateParameterValue = parameter.getValue()[0];
                break;
            }
        }

        // Extract 'Principal' from the presented certificate.
        if (certificateParameterValue != null) {
            username = ExtractUserFromSSHCertificate(certificateParameterValue);
        }

        if (username == null) {
            throw new IdentityOAuth2Exception("Principal was not found in the provided certificate.");
        }

        UserStoreManager userStoreManager = getUserStoreManager(oAuthTokenReqMessageContext.getOauth2AccessTokenReqDTO()
                .getTenantDomain());

        try {
            if (userStoreManager != null) {
                // Check whether the 'Principal' is an existing user.
                if (!userStoreManager.isExistingUser(username)) {
                    throw new IdentityOAuth2Exception("User: " + username + " does not exist.");
                }

                // Retrieve 'accountLocked' and 'accountDisabled' claim of user.
                Map<String, String> userClaimValues = userStoreManager.getUserClaimValues(username,
                        new String[]{ACCOUNT_LOCKED_CLAIM, ACCOUNT_DISABLED_CLAIM}, null);

                String accountLockedClaimValue = userClaimValues.get(ACCOUNT_LOCKED_CLAIM);
                String accountDisabledClaimValue = userClaimValues.get(ACCOUNT_DISABLED_CLAIM);

                // Check if user is locked.
                if (StringUtils.isNotEmpty(accountLockedClaimValue) && Boolean.parseBoolean(accountLockedClaimValue)) {
                    throw new IdentityOAuth2Exception("User: " + username + " is locked.");
                }

                // Check if user is disabled.
                if (StringUtils.isNotEmpty(accountDisabledClaimValue) && Boolean.parseBoolean(accountDisabledClaimValue)) {
                    throw new IdentityOAuth2Exception("User: " + username + " is disabled.");
                }
            }
        } catch (UserStoreException e) {
            throw new IdentityOAuth2Exception("Error occurred while performing user store operation.", e);
        }

        AuthenticatedUser user = OAuth2Util.getUserFromUserName(username);
        user.setAuthenticatedSubjectIdentifier(user.toString());
        oAuthTokenReqMessageContext.setAuthorizedUser(user);
        oAuthTokenReqMessageContext.setScope(oAuthTokenReqMessageContext.getOauth2AccessTokenReqDTO().getScope());

        return true;
    }

    private UserStoreManager getUserStoreManager(String tenantDomain)
            throws IdentityOAuth2Exception {

        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);

        try {
            return GrantHandlerServiceComponent.getRealmService().getTenantUserRealm(tenantId).getUserStoreManager();

        } catch (UserStoreException e) {
            throw new IdentityOAuth2Exception("Error occurred while getting the user store manager.", e);
        }
    }

    private String ExtractUserFromSSHCertificate(String sshCertificate) {

        String[] split = sshCertificate.trim().split("\\s+");
        byte[] encodedCert = java.util.Base64.getMimeDecoder().decode(split[1].getBytes(UTF_8));

        Buffer.PlainBuffer plainBuffer = new Buffer.PlainBuffer(encodedCert);
        String certificateType;

        try {
            certificateType = plainBuffer.readString();
        } catch (Buffer.BufferException e) {
            log.error(e);
            return null;
        }

        if (SSH_CERT_TYPE_ED25519.equals(certificateType)) {
            KeyType keyType = KeyType.fromString(SSH_CERT_TYPE_ED25519);
            PublicKey publicKey;

            try {
                publicKey = keyType.readPubKeyFromBuffer(plainBuffer);

                if (log.isDebugEnabled()) {
                    log.debug("PublicKey algorithm from certificate: " + publicKey.getAlgorithm());
                }

                if (publicKey instanceof Certificate) {
                    Certificate certificate = (Certificate) publicKey;
                    List<String> validPrincipals = certificate.getValidPrincipals();

                    if (validPrincipals != null && !validPrincipals.isEmpty()) {
                        String principal = validPrincipals.get(0);

                        if (log.isDebugEnabled()) {
                            log.debug("User principal from certificate: " + principal);
                        }
                        return principal;
                    }
                }
            } catch (GeneralSecurityException e) {
                log.error(e);
            }
        }
        return null;
    }

    @Override
    public boolean authorizeAccessDelegation(OAuthTokenReqMessageContext tokReqMsgCtx)
            throws IdentityOAuth2Exception {

        return true;
    }

    @Override
    public boolean validateScope(OAuthTokenReqMessageContext tokReqMsgCtx)
            throws IdentityOAuth2Exception {

        return true;
    }
}
