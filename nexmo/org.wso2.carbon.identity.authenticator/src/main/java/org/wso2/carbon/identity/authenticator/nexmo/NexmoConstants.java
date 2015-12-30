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

public class NexmoConstants {
    public static final String AUTHENTICATOR_NAME = "NexmoAuthenticator";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "Nexmo";
    public static final String NEXMO_LOGIN_PAGE = "/authenticationendpoint/nexmo_login.jsp";

    public static final String NEXMO_VERIFY_REQUEST_URL = "https://api.nexmo.com/verify/json";
    public static final String NEXMO_VERIFY_CHECK_URL = "https://api.nexmo.com/verify/check/json?";

    public static final String NEXMO_API_KEY = "apiKey";
    public static final String NEXMO_API_SECRET = "apiSecret";
    public static final String NEXMO_REQUEST_ID  = "requestId";
    public static final String NEXMO_BRAND  = "brand";
    public static final String NEXMO_PIN_EXPIRY  = "NEXMOMethod";
    public static final String NEXMO_PIN  = "pin";
    public static final String NEXMO_CODE_LENGTH  = "NEXMOMethod";
}