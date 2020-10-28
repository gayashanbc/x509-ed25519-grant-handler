/*
 * Copyright (c) WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AbstractAuthorizationGrantHandler;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.sample.identity.oauth2.grant.ed25519.model.sshj.Buffer;
import org.wso2.sample.identity.oauth2.grant.ed25519.model.sshj.KeyType;

import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.util.List;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * X509 grant type for Identity Server
 */
public class X509GrantHandler extends AbstractAuthorizationGrantHandler  {

    public static final String SSH_CERT_TYPE_ED25519 = "ssh-ed25519-cert-v01@openssh.com";
    private static Log log = LogFactory.getLog(X509GrantHandler.class);
    public static final String X509_GRANT_PARAM = "x509";

    @Override
    public boolean validateGrant(OAuthTokenReqMessageContext oAuthTokenReqMessageContext)  throws
            IdentityOAuth2Exception {

        boolean authStatus = false;
        // extract request parameters
        RequestParameter[] parameters = oAuthTokenReqMessageContext.getOauth2AccessTokenReqDTO().getRequestParameters();
        String certParam = null;
        String subjectDN = null;
        // find out subjectDN
        for(RequestParameter parameter : parameters){
            if(X509_GRANT_PARAM.equals(parameter.getKey())){
                if(parameter.getValue() != null && parameter.getValue().length > 0){
                    certParam = parameter.getValue()[0];
                }
            } else if("subjectDN".equalsIgnoreCase(parameter.getKey())) {
                if(parameter.getValue() != null && parameter.getValue().length > 0){
                    subjectDN = parameter.getValue()[0];
                }
            }
        }

        String username = null;
        if(subjectDN != null) {
            username = subjectDN;
            log.debug("Username is retrieved from Subject DN : " + username);
        } else {
            if (certParam != null) {
                username = getUserFromSSHCert(certParam);
                log.debug("Username is retrieved from Certificate : " + username);
            }
        }
        if (username != null) {
            // if valid set authorized mobile number as grant user
            AuthenticatedUser user = OAuth2Util.getUserFromUserName(username);
            user.setAuthenticatedSubjectIdentifier(user.toString());
            oAuthTokenReqMessageContext.setAuthorizedUser(user);
            oAuthTokenReqMessageContext.setScope(oAuthTokenReqMessageContext.getOauth2AccessTokenReqDTO().getScope());
            authStatus = true;
        }
        return authStatus;
    }

    private String getUserFromSSHCert(String sshCertificate) {

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

        if(SSH_CERT_TYPE_ED25519.equals(certificateType)) {
            KeyType keyType = KeyType.fromString(SSH_CERT_TYPE_ED25519);
            PublicKey publicKey;
            try {
                publicKey = keyType.readPubKeyFromBuffer(plainBuffer);

                if (log.isDebugEnabled()) {
                    log.debug("PublicKey algorithm " + publicKey.getAlgorithm());
                }

                if (publicKey instanceof Certificate) {
                    Certificate certificate = (Certificate) publicKey;

                    List<String> validPrincipals = certificate.getValidPrincipals();
                    if (validPrincipals != null && !validPrincipals.isEmpty()) {
                        String principal = validPrincipals.get(0);
                        if (log.isDebugEnabled()) {
                            log.debug("User principal from cert: " + principal);
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

    public boolean authorizeAccessDelegation(OAuthTokenReqMessageContext tokReqMsgCtx)
            throws IdentityOAuth2Exception {

        return true;
    }
    public boolean validateScope(OAuthTokenReqMessageContext tokReqMsgCtx)
            throws IdentityOAuth2Exception {

        return true;
    }
}

