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

package org.wso2.sample.identity.oauth2.grant.ed25519.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.sample.identity.oauth2.grant.ed25519.X509GrantHandler;

@Component(name = "org.wso2.sample.identity.oauth2.grant.ed25519.internal.GrantHandlerServiceComponent",
        immediate = true)
public class GrantHandlerServiceComponent {

    private static RealmService realmService = null;
    private static Log logger = LogFactory.getLog(X509GrantHandler.class);

    @Activate
    protected void activate(BundleContext bundleContext) {

        logger.info("org.wso2.sample.identity.oauth2.grant.ed25519.internal.GrantHandlerServiceComponent is " +
                "activated");
    }

    /**
     * Set realm service implementation
     *
     * @param realmService RealmService
     */
    @Reference(
            name = "user.realmservice.default",
            service = org.wso2.carbon.user.core.service.RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService")
    protected void setRealmService(RealmService realmService) {

        if (logger.isDebugEnabled()) {
            logger.debug("realmService set in " +
                    "org.wso2.sample.identity.oauth2.grant.ed25519.internal.GrantHandlerServiceComponent bundle");
        }
        GrantHandlerServiceComponent.realmService = realmService;
    }

    /**
     * Unset realm service implementation
     */
    protected void unsetRealmService(RealmService realmService) {

        if (logger.isDebugEnabled()) {
            logger.debug("realmService unset in " +
                    "org.wso2.sample.identity.oauth2.grant.ed25519.internal.GrantHandlerServiceComponent bundle");
        }
        GrantHandlerServiceComponent.realmService = null;
    }

    public static RealmService getRealmService() {

        return realmService;
    }
}
