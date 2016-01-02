/*
 *  Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */

package org.wso2.carbon.identity.authenticator.authy;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Authenticator of AuthyOneTouch
 */
public class AuthyOneTouchAuthenticator extends AbstractApplicationAuthenticator
        implements FederatedApplicationAuthenticator {

    private static Log log = LogFactory.getLog(AuthyOneTouchAuthenticator.class);
    private Map<String, String> authenticatorProperties;

    /**
     * Check whether the authentication or logout request can be handled by the authenticator
     */
    //@Override
    public boolean canHandle(HttpServletRequest request) {
        if (log.isDebugEnabled()) {
            log.debug("Inside AuthyAuthenticator.canHandle()");
        }
        System.out.println("-----------------------------------------------------");
        System.out.println("canHandle Hello to all");
        String authyOneTouch = request.getParameter("authyOneTouch");

        return authyOneTouch != null;
    }

    /**
     * initiate the authentication request
     */
    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request,
                                                 HttpServletResponse response,
                                                 AuthenticationContext context)
            throws AuthenticationFailedException {
        //Add your code here to initiate the request
        System.out.println("Initiate: -----------------------------------------------------");
        String authyId = getClaim(context);
        log.info(authyId);
        authenticatorProperties = context.getAuthenticatorProperties();
        String loginPage = "/authenticationendpoint/authyonetouch.jsp";
        String queryParams = FrameworkUtils
                .getQueryStringWithFrameworkContextId(context.getQueryParams(),
                                                      context.getCallerSessionKey(),
                                                      context.getContextIdentifier());

        String retryParam = "";

        if (context.isRetrying()) {
            retryParam = "&authFailure=true&authFailureMsg=login.fail.message";
        }

        try {
            response.sendRedirect(response.encodeRedirectURL(loginPage + ("?" + queryParams))
                                  + "&authyId=" + authyId + "&authenticators=" + getName() + retryParam);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Get the configuration properties of UI
     */
    @Override
    public List<Property> getConfigurationProperties() {
        List<Property> configProperties = new ArrayList<Property>();

        Property apiKey = new Property();
        apiKey.setName(AuthyConstants.AUTHY_APIKEY);
        apiKey.setDisplayName("API Key");
        apiKey.setRequired(true);
        apiKey.setDescription("Enter Authy API key value");
        apiKey.setDisplayOrder(1);
        configProperties.add(apiKey);

        Property expiryTime = new Property();
        expiryTime.setName(AuthyConstants.AUTHY_EXPIRY_TIME);
        expiryTime.setDisplayName("Expiry Time");
        expiryTime.setRequired(true);
        expiryTime.setDescription("Enter the expiry time (in seconds)");
        expiryTime.setDisplayOrder(2);
        configProperties.add(expiryTime);

        Property message = new Property();
        message.setName(AuthyConstants.AUTHY_MESSAGE);
        message.setDisplayName("Message");
        message.setRequired(true);
        message.setDescription("Enter the message shown to the user");
        message.setDisplayOrder(3);
        configProperties.add(message);

        Property logoUrl = new Property();
        logoUrl.setName(AuthyConstants.AUTHY_LOGO_URL);
        logoUrl.setDisplayName("Logo URL");
        logoUrl.setRequired(true);
        logoUrl.setDescription("Enter the logo URL");
        logoUrl.setDisplayOrder(4);
        configProperties.add(logoUrl);

        Property logoResolution = new Property();
        logoResolution.setName(AuthyConstants.AUTHY_LOGO_RESOLUTION);
        logoResolution.setDisplayName("Logo Resolution");
        logoResolution.setRequired(true);
        logoResolution.setDescription("Enter the logo resolution (default, low, med, high)");
        logoResolution.setDisplayOrder(5);
        configProperties.add(logoResolution);

        return configProperties;
    }

    /**
     * Process the response of the Authy end-point
     */
    @Override
    protected void processAuthenticationResponse(HttpServletRequest request,
                                                 HttpServletResponse response,
                                                 AuthenticationContext context)
            throws AuthenticationFailedException {
        try {
            boolean isAuthenticated = false;

            String authyId = request.getParameter(AuthyConstants.AUTHY_ID);
            String s = new AuthyTransactions().createApprovalRequest(authyId, authenticatorProperties.get(AuthyConstants.AUTHY_APIKEY), "Hello", "aaa", "bbb");
            JsonObject responseJson = new JsonParser().parse(s).getAsJsonObject();
            String transactionStatus = responseJson.getAsJsonPrimitive(AuthyConstants.AUTHY_SUCCESS).getAsString();
            if (transactionStatus.equals(AuthyConstants.AUTHY_TRUE)) {
                System.out.println("Process: -----------------------------------------------------");
                System.out.println(transactionStatus);

                String uuid = responseJson.getAsJsonObject(AuthyConstants.AUTHY_APPROVAL_REQUEST).getAsJsonPrimitive(AuthyConstants.AUTHY_UUID).getAsString();

                log.info("Transaction status uuid1:" + uuid);

                int retry = 0;
                int retryInterval = 1;
                int retryCount = Integer.parseInt(authenticatorProperties.get(AuthyConstants.AUTHY_EXPIRY_TIME)) / retryInterval;
                while (retry < retryCount) {
                    String responseString = new AuthyTransactions().checkApprovalRequestStatus(uuid, authenticatorProperties.get(AuthyConstants.AUTHY_APIKEY));
                    if (!responseString.equals(AuthyConstants.FAILED)) {
                        JsonObject transactionStatusResponse = new JsonParser().parse(responseString).getAsJsonObject();
                        String approvalRequestStatus = transactionStatusResponse.getAsJsonPrimitive(AuthyConstants.AUTHY_SUCCESS).getAsString();

                        if (log.isDebugEnabled()) {
                            log.debug("Transaction status :" + approvalRequestStatus);
                        }
                        log.info("Transaction status :" + approvalRequestStatus);
                        if (transactionStatus.equals(AuthyConstants.AUTHY_TRUE)) {
                            String approvalRequest = transactionStatusResponse.getAsJsonObject(AuthyConstants.AUTHY_APPROVAL_REQUEST).getAsJsonPrimitive(AuthyConstants.AUTHY_STATUS).getAsString();
                            log.debug("Transaction status approvalRequest :" + approvalRequest);
                            if (approvalRequest.equals(AuthyConstants.AUTHY_APPROVED)) {
                                isAuthenticated = true;
                                break;
                            } else if (approvalRequest.equals(AuthyConstants.AUTHY_DENIED)) {
                                break;
                            }
                        }
                        Thread.sleep(1000);
                        retry++;
                    }
                }
                if (isAuthenticated) {
                    context.setSubject(AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(authyId));
                } else {
                    throw new AuthenticationFailedException("Unable to confirm the MePIN transaction");
                }

            } else {
                throw new AuthenticationFailedException("Can not confirm authorization code.");
            }
        } catch (InterruptedException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Get the friendly name of the Authenticator
     */
    //@Override
    public String getFriendlyName() {
        return AuthyConstants.AUTHY_ONE_TOUCH_AUTHENTICATOR_FRIENDLY_NAME;
    }

    /**
     * Get the name of the Authenticator
     */
    // @Override
    public String getName() {
        return AuthyConstants.AUTHY_AUTHENTICATOR_ONE_TOUCH_NAME;
    }

    /**
     * Get the Context identifier sent with the request.
     */
    public String getContextIdentifier(HttpServletRequest request) {
        //Add your code here
        return request.getParameter(FrameworkConstants.SESSION_DATA_KEY);
    }

    public String getClaim(AuthenticationContext context) throws AuthenticationFailedException {
        String username = null;
        String authyId = null;

        //Getting the last authenticated local user
        for (Integer stepMap : context.getSequenceConfig().getStepMap().keySet()) {
            if (context.getSequenceConfig().getStepMap().get(stepMap).getAuthenticatedUser() != null &&
                context.getSequenceConfig().getStepMap().get(stepMap).getAuthenticatedAutenticator()
                        .getApplicationAuthenticator() instanceof LocalApplicationAuthenticator) {
                username = String.valueOf(context.getSequenceConfig().getStepMap().get(stepMap).getAuthenticatedUser());
                break;
            }
        }
        if (username != null) {
            UserRealm userRealm = null;
            try {
                String tenantDomain = MultitenantUtils.getTenantDomain(username);
                int tenantId = IdentityTenantUtil.getTenantIdOfUser(username);
                RealmService realmService = IdentityTenantUtil.getRealmService();
                userRealm = (UserRealm) realmService.getTenantUserRealm(tenantId);
                username = MultitenantUtils.getTenantAwareUsername(username);
                if (userRealm != null) {
                    authyId = userRealm.getUserStoreManager().getUserClaimValue(username, AuthyConstants.AUTHY_ID_CLAIM_URI,
                                                                                null).toString();
                } else {
                    throw new AuthenticationFailedException(
                            "Cannot find the user claim for the given username");
                }
            } catch (org.wso2.carbon.user.api.UserStoreException e) {
                throw new AuthenticationFailedException(
                        "Cannot find the user claim for the given username");
            }
        }
        return authyId;
    }
}

