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

        logger.info("org.wso2.sample.identity.oauth2.grant.ed25519.internal.GrantHandlerServiceComponent is activated");
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
            logger.debug("realmService set in SCIMCommonComponent bundle");
        }
        GrantHandlerServiceComponent.realmService = realmService;
    }

    /**
     * Unset realm service implementation
     */
    protected void unsetRealmService(RealmService realmService) {

        if (logger.isDebugEnabled()) {
            logger.debug("realmService unset in SCIMCommonComponent bundle");
        }
        GrantHandlerServiceComponent.realmService = null;
    }

    public static RealmService getRealmService() {

        return realmService;
    }
}
