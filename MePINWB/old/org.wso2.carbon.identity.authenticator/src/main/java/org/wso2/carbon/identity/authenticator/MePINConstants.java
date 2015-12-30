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

public class MePINConstants {
    public static final String AUTHENTICATOR_NAME = "MePINAuthenticator";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "mepin";

    public static final String MEPIN_CREATE_TRANSACTION_URL = "https://api.mepin.com/transactions/create";
    public static final String MEPIN_GET_TRANSACTION_URL = "https://api.mepin.com/transactions/show";
    public static final String MEPIN_GET_USER_INFO_URL = "https://api.mepin.com/simple_api/user_info";

    public static final String MEPIN_CLIENT_ID = "ClientId";
    public static final String MEPIN_USERNAME = "Username";
    public static final String MEPIN_PASSWORD = "Password";
    public static final String MEPIN_SHORT_MESSAGE = "ShortMessage";
    public static final String MEPIN_MESSAGE = "Message";
    public static final String MEPIN_EXPIRY_TIME = "ExpiryTime";
    public static final String MEPIN_CALLBACK_URL = "CallbackUrl";
    public static final String MEPIN_HEADER = "Header";
    public static final String MEPIN_CONFIRMATION_POLICY = "ConfirmationPolicy";
    public static final String MEPIN_QUERY = "identifier=%s&short_message=%s&header=%s&message=%s&client_id=%s&account=%s&expiry_time=%s&callback_url=%s&confirmation_policy=%s";
    public static final String MEPIN_ID_NOT_FOUND = "MePIN Id is not found. Authentication failed";

    public static final String HTTP_GET = "GET";
    public static final String HTTP_ACCEPT = "Accept";
    public static final String HTTP_ACCEPT_CHARSET = "Accept-Charset";
    public static final String HTTP_AUTHORIZATION= "Authorization";
    public static final String HTTP_AUTHORIZATION_BASIC= "Basic ";
    public static final String HTTP_CONTENT_TYPE= "application/json";
    public static final String HTTP_POST_CONTENT_TYPE= "application/x-www-form-urlencoded;charset=UTF-8";
    public static final String CHARSET = "UTF-8";


}