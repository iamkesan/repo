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
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.InvalidCredentialsException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.Property;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Authenticator of Authy
 */
public class AuthyPhoneAuthenticator extends AbstractApplicationAuthenticator
        implements FederatedApplicationAuthenticator {

    private static Log log = LogFactory.getLog(AuthyPhoneAuthenticator.class);
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
        String confirmationCode = request.getParameter("confirmationCode");

        return confirmationCode != null;
    }

    /**
     * initiate the authentication request
     */
    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request,
                                                 HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {
        authenticatorProperties = context.getAuthenticatorProperties();
        System.out.println("Initiate: -----------------------------------------------------");
        String loginPage = "/authenticationendpoint/authy.jsp";
        String queryParams = FrameworkUtils
                .getQueryStringWithFrameworkContextId(context.getQueryParams(),
                                                      context.getCallerSessionKey(),
                                                    context.getContextIdentifier());
        try {
            String s = new AuthyTransactions().sendToken(AuthyConstants.AUTHY_METHOD_CALL, "8632251", authenticatorProperties.get(AuthyConstants.AUTHY_APIKEY));
        System.out.println(s);
        System.out.println("s");
        String retryParam = "";

        if (context.isRetrying()) {
            retryParam = "&authFailure=true&authFailureMsg=login.fail.message";
        }


            response.sendRedirect(response.encodeRedirectURL(loginPage + ("?" + queryParams))
                                  + "&authenticators=" + getName() + ":" + "LOCAL" + retryParam);
        } catch (IOException e) {
            e.printStackTrace();
        }
        catch (NullPointerException e) {
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
        configProperties.add(apiKey);
        return configProperties;
    }

    /**
     * Process the response of the Authy end-point
     */
    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
        AuthenticationContext context) throws AuthenticationFailedException {
        String confirmationCode = request.getParameter("confirmationCode");
        String s=new AuthyTransactions().verifyToken(confirmationCode,"8632251", authenticatorProperties.get(AuthyConstants.AUTHY_APIKEY));
        boolean isAuthenticated = false;
        JsonObject responseJson = new JsonParser().parse(s).getAsJsonObject();
        System.out.println(responseJson);
        log.debug("MePin JSON Response: " + responseJson);
        String transactionStatus= responseJson.getAsJsonPrimitive(AuthyConstants.AUTHY_TOKEN).getAsString();

        if (transactionStatus.equals(AuthyConstants.AUTHY_IS_VALID)) {
            System.out.println("Process: -----------------------------------------------------");
            System.out.println(transactionStatus);
            isAuthenticated=true;
        } else {
            throw new AuthenticationFailedException("Can not confirm authorization code.");
        }

        if (!isAuthenticated) {
            if (log.isDebugEnabled()) {
                log.debug("user authentication failed due to invalid credentials.");
            }

            throw new InvalidCredentialsException("user authentication failed due to invalid credentials.");
        }
        else context.setSubject(AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier("8632251"));
    }

    /**
     * Get the friendly name of the Authenticator
     */
    //@Override
    public String getFriendlyName() {
        return AuthyConstants.AUTHY_PHONE_AUTHENTICATOR_FRIENDLY_NAME;
    }

    /**
     * Get the name of the Authenticator
     */
   // @Override
    public String getName() {
        return AuthyConstants.AUTHY_AUTHENTICATOR_PHONE_NAME;
    }

    /**
     * Get the Context identifier sent with the request.
     */
    public String getContextIdentifier(HttpServletRequest request) {
        //Add your code here
        return request.getParameter(FrameworkConstants.SESSION_DATA_KEY);
    }


}

