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

package org.wso2.carbon.identity.authenticator.nexmo;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.Property;

import javax.net.ssl.HttpsURLConnection;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Authenticator of Nexmo
 */
public class NexmoAuthenticator extends AbstractApplicationAuthenticator
        implements FederatedApplicationAuthenticator {

    private static Log log = LogFactory.getLog(NexmoAuthenticator.class);
    private Map<String, String> authenticatorProperties;

    /**
     * Check whether the authentication or logout request can be handled by the authenticator
     */
    //@Override
    public boolean canHandle(HttpServletRequest request) {
        if (log.isDebugEnabled()) {
            log.debug("Inside NexmoAuthenticator.canHandle()");
        }
        String confirmationCode = request.getParameter(NexmoConstants.NEXMO_PIN);

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
        String loginPage = "/authenticationendpoint/nexmo_login.jsp";
        String queryParams = FrameworkUtils.getQueryStringWithFrameworkContextId(
                context.getQueryParams(), context.getCallerSessionKey(),
                context.getContextIdentifier());

        String s=sendPin();
        JsonObject responseJson = new JsonParser().parse(s).getAsJsonObject();
        String requestId= responseJson.getAsJsonPrimitive("request_id").getAsString();
        String retryParam = "";

        if (context.isRetrying()) {
            retryParam = "&authFailure=true&authFailureMsg=login.fail.message";
        }

        try {
            response.sendRedirect(response.encodeRedirectURL(loginPage + ("?" + queryParams)) + "&authenticators=" +
            getName() + retryParam+"&requestId="+requestId);
        } catch (IOException e) {
            log.error("Authentication failed!", e);
            throw new AuthenticationFailedException(e.getMessage(), e);
        }
    }

    /**
     * Get the configuration properties of UI
     */
    @Override
    public List<Property> getConfigurationProperties() {
        List<Property> configProperties = new ArrayList<Property>();
        //Add your code here for UI fields
        return configProperties;
    }

    /**
     * Process the response of the Nexmo end-point
     */
    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {
        String pin = request.getParameter(NexmoConstants.NEXMO_PIN);
        String requestId = request.getParameter("requestId");


        String s=verifyPin(requestId, pin);

        JsonObject responseJson = new JsonParser().parse(s).getAsJsonObject();
        String status= responseJson.getAsJsonPrimitive("status").getAsString();

        if(status.equals("0")){
            context.setSubject("User is logged in");
        }
        else throw new AuthenticationFailedException("Can not confirm the pin.");
    }

    /**
     * Get the friendly name of the Authenticator
     */
    //@Override
    public String getFriendlyName() {
        return NexmoConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    /**
     * Get the name of the Authenticator
     */
    //@Override
    public String getName() {
        return NexmoConstants.AUTHENTICATOR_NAME;
    }

    /**
     * Get the Context identifier sent with the request.
     */
    public String getContextIdentifier(HttpServletRequest request) {
        //Add your code here
        return request.getParameter(FrameworkConstants.SESSION_DATA_KEY);
    }

    public String verifyPin(String requestId,String pin){

        String url="https://api.nexmo.com/verify/check/json?api_key=8980069a&api_secret=d2e6da70&request_id="+requestId+"&code="+pin;

        String responseString = "";

        try {
            HttpsURLConnection connection = (HttpsURLConnection) new URL(url).openConnection();

            int status = connection.getResponseCode();

            if (log.isDebugEnabled()) {
                log.debug("Nexmo Response Code :" + status);
            }

            BufferedReader br = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) {
                sb.append(line).append("\n");
            }
            br.close();
            responseString = sb.toString();
            log.info("Nexmo Response :" + responseString);

        } catch (IOException e) {
            e.printStackTrace();
        }

        return responseString;
    }

    public String sendPin(){

        String url="https://api.nexmo.com/verify/json?api_key=8980069a&api_secret=d2e6da70&number=94779758021&brand=NexmoVerifyTest";
        String responseString = "";

        try {
            HttpsURLConnection connection = (HttpsURLConnection) new URL(url).openConnection();

            int status = connection.getResponseCode();

            if (log.isDebugEnabled()) {
                log.debug("Nexmo Response Code :" + status);
            }

            BufferedReader br = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) {
                sb.append(line).append("\n");
            }
            br.close();
            responseString = sb.toString();
            log.info("Nexmo Response :" + responseString);

        } catch (IOException e) {
            e.printStackTrace();
        }

        return responseString;
    }

    protected boolean retryAuthenticationEnabled() {
        return true;
    }
}

