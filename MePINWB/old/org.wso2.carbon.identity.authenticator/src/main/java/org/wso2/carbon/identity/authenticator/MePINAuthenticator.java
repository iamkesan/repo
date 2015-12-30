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

package org.wso2.carbon.identity.authenticator;

import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.user.profile.mgt.UserProfileException;
import org.wso2.carbon.user.core.UserCoreConstants;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Authenticator of MePIN
 */
public class MePINAuthenticator extends AbstractApplicationAuthenticator
        implements FederatedApplicationAuthenticator {

    private static Log log = LogFactory.getLog(MePINAuthenticator.class);

    /**
     * Check whether the authentication or logout request can be handled by the authenticator
     */
    // @Override
    public boolean canHandle(HttpServletRequest request) {
        if (log.isDebugEnabled()) {
            log.debug("Inside MePINAuthenticator.canHandle()");
        }
        return true;
    }

    /**
     * initiate the authentication request
     */
    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request, HttpServletResponse response,
                                           AuthenticationContext context) throws AuthenticationFailedException,
            LogoutFailedException {
        if (context.isLogoutRequest()) {
                return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        } else {
            context.setRetrying(false);
            String allowStatus = "";
            boolean isAuthenticated = false;
            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
            try {

                String authenticatedLocalUsername = getLocalAuthenticatedUser(context).getUserName();

                //String mePinId = "41b21e2af200fcf75a8442bc93a0d27b";
                String mePinId = "fcf3c2b42ee0ca79015e92d76eb432f6";
                JsonObject transactionResponse = new MePINTransaction().createTransaction(mePinId, context.getContextIdentifier(),
                        MePINConstants.MEPIN_CREATE_TRANSACTION_URL, authenticatorProperties.get(MePINConstants.MEPIN_USERNAME),
                        authenticatorProperties.get(MePINConstants.MEPIN_PASSWORD),
                        authenticatorProperties.get(MePINConstants.MEPIN_CLIENT_ID),
                        authenticatorProperties.get(MePINConstants.MEPIN_HEADER),
                        authenticatorProperties.get(MePINConstants.MEPIN_MESSAGE),
                        authenticatorProperties.get(MePINConstants.MEPIN_SHORT_MESSAGE),
                        authenticatorProperties.get(MePINConstants.MEPIN_CONFIRMATION_POLICY),
                        authenticatorProperties.get(MePINConstants.MEPIN_CALLBACK_URL),
                        authenticatorProperties.get(MePINConstants.MEPIN_EXPIRY_TIME));
                String transactionId = transactionResponse.getAsJsonPrimitive("transaction_id").getAsString();
                String status = transactionResponse.getAsJsonPrimitive("status").getAsString();//TODO constants

                if (status.equalsIgnoreCase("ok")) {
                    if (log.isDebugEnabled()) {
                        log.debug("Successfully created the MePIN transaction");
                    }
                    int retry = 0;
                    int retryInterval = 1;
                    int retryCount = Integer.parseInt(authenticatorProperties.get(MePINConstants.MEPIN_EXPIRY_TIME)) / retryInterval;
                    while (retry < retryCount) {
                        JsonObject transactionStatusResponse = new MePINTransaction().getTransaction(MePINConstants.MEPIN_GET_TRANSACTION_URL,
                                transactionId, authenticatorProperties.get(MePINConstants.MEPIN_CLIENT_ID),
                                authenticatorProperties.get(MePINConstants.MEPIN_USERNAME),
                                authenticatorProperties.get(MePINConstants.MEPIN_PASSWORD));

                        String transactionStatus = transactionStatusResponse.getAsJsonPrimitive("transaction_status").getAsString();
                        JsonPrimitive allowObject = transactionStatusResponse.getAsJsonPrimitive("allow");
                        if (log.isDebugEnabled()) {
                            log.debug("Transaction status :"+transactionStatus);
                        }
                        if (transactionStatus.equals("completed")) {
                            allowStatus = allowObject.getAsString();
                            if (Boolean.parseBoolean(allowStatus)) {
                                isAuthenticated = true;
                                break;
                            }
                        }
                        Thread.sleep(1000);
                        retry++;
                    }
                    if (isAuthenticated) {
                        //context.setSubject("User is logged in");
                        String username = "admin";
                        context.setSubject(AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(username));
                    } else throw new AuthenticationFailedException("Error while creating the MePIN transaction");
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("Error while creating the MePIN transaction");
                    }
                    throw new AuthenticationFailedException("Error while creating the MePIN transaction");//TODO remove same msg
                }
            } catch (IOException e) {
                throw new AuthenticationFailedException(e.getMessage(), e);//TODO remove and add constant msg
            } catch (InterruptedException e) {
                e.printStackTrace();//TODO handle

            }
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        }
    }

    /**
     * Get the configuration properties of UI
     */
    // @Override
    public List<Property> getConfigurationProperties() {

        List<Property> configProperties = new ArrayList<Property>();
        Property username = new Property();
        username.setName(MePINConstants.MEPIN_USERNAME);
        username.setDisplayName("Username");
        username.setRequired(true);
        username.setDescription("Enter username");
        configProperties.add(username);

        Property password = new Property();
        password.setName(MePINConstants.MEPIN_PASSWORD);
        password.setDisplayName("Password");
        password.setRequired(true);
        password.setConfidential(true);
        password.setDescription("Enter password");
        configProperties.add(password);

        Property clientId = new Property();
        clientId.setName(MePINConstants.MEPIN_CLIENT_ID);
        clientId.setDisplayName("Client Id");
        clientId.setRequired(true);
        clientId.setDescription("Enter Client Id");
        configProperties.add(clientId);

        Property callbackUrl = new Property();
        callbackUrl.setName(MePINConstants.MEPIN_CALLBACK_URL);
        callbackUrl.setDisplayName("Callback Url");
        callbackUrl.setRequired(true);
        callbackUrl.setDescription("Enter Callback Url");
        configProperties.add(callbackUrl);

        Property confirmationPolicy = new Property();
        confirmationPolicy.setName(MePINConstants.MEPIN_CONFIRMATION_POLICY);
        confirmationPolicy.setDisplayName("Confirmation Policy");
        confirmationPolicy.setRequired(true);
        confirmationPolicy.setDescription("Enter Confirmation Policy");
        configProperties.add(confirmationPolicy);

        Property expiryTime = new Property();
        expiryTime.setName(MePINConstants.MEPIN_EXPIRY_TIME);
        expiryTime.setDisplayName("Expiry Time");
        expiryTime.setRequired(true);
        expiryTime.setDescription("Enter Expiry Time (in seconds)");
        configProperties.add(expiryTime);

        Property header = new Property();
        header.setName(MePINConstants.MEPIN_HEADER);
        header.setDisplayName("Header");
        header.setRequired(true);
        header.setDescription("Enter Header");
        configProperties.add(header);

        Property shortMessage = new Property();
        shortMessage.setName(MePINConstants.MEPIN_SHORT_MESSAGE);
        shortMessage.setDisplayName("Short Message");
        shortMessage.setRequired(true);
        shortMessage.setDescription("Enter Short Message");
        configProperties.add(shortMessage);

        Property message = new Property();
        message.setName(MePINConstants.MEPIN_MESSAGE);
        message.setDisplayName("Message");
        message.setRequired(true);
        message.setDescription("Enter Message");
        configProperties.add(message);

        return configProperties;
    }

    /**
     * Process the response of the MePIN end-point
     **/
    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {
        //Add your code here
    }

    /**
     * Get the friendly name of the Authenticator
     */
    // @Override
    public String getFriendlyName() {
        return MePINConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    /**
     * Get the name of the Authenticator
     */
    //@Override
    public String getName() {
        return MePINConstants.AUTHENTICATOR_NAME;
    }

    /**
     * Get the Context identifier sent with the request.
     */
    public String getContextIdentifier(HttpServletRequest request) {
        return request.getParameter(FrameworkConstants.SESSION_DATA_KEY);
    }

    private AuthenticatedUser getLocalAuthenticatedUser(AuthenticationContext context) {
        //username from authentication context.
        AuthenticatedUser authenticatedUser = null;
        for (int i = 1; i <= context.getSequenceConfig().getStepMap().size(); i++) {
            StepConfig stepConfig = context.getSequenceConfig().getStepMap().get(i);
            if (stepConfig.getAuthenticatedUser() != null && stepConfig.getAuthenticatedAutenticator()
                    .getApplicationAuthenticator() instanceof LocalApplicationAuthenticator) {
                authenticatedUser = stepConfig.getAuthenticatedUser();
                if (authenticatedUser.getUserStoreDomain() == null) {
                    authenticatedUser.setUserStoreDomain(UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME);
                }
                if (log.isDebugEnabled()) {
                    log.debug("username :" + authenticatedUser.toString());
                }
                break;
            }
        }
        return authenticatedUser;
    }

    private String[] getMepinIdAssociatedWith(String idpID, String associatedID) throws
                                                                              UserProfileException {
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        String sql = null;
        String username = "";
        int tenantID = CarbonContext.getThreadLocalCarbonContext().getTenantId();

        String usernames = "";
        try {
            sql = "SELECT IDP_USER_IDDOMAIN_NAME, USER_NAME FROM IDN_ASSOCIATED_ID WHERE TENANT_ID = ? " +
                  "AND IDP_ID = (SELECT ID FROM IDP WHERE NAME = ? AND TENANT_ID = ?) AND IDP_USER_ID = ?";
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setInt(1, tenantID);
            prepStmt.setString(2, idpID);
            prepStmt.setInt(3, tenantID);
            prepStmt.setString(4, associatedID);
            ResultSet resultSet = prepStmt.executeQuery();
            connection.commit();
            int i = 0;
            while (resultSet.next()) {
                String domainName = resultSet.getString(1);
                username = resultSet.getString(2);
                if (!"PRIMARY".equals(domainName)) {
                    username = domainName + "/" + username;
                }
                usernames = StringUtils.isEmpty(usernames) ? username : usernames + "," + username;
                i++;
            }
        } catch (SQLException e) {
            log.error("Error occurred while getting associated name", e);
            throw new UserProfileException("Error occurred while getting associated name", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, (ResultSet) null, prepStmt);
        }
        return usernames.split(",");
    }
}