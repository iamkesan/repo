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

public class AuthyConstants {

    public static final String AUTHY_AUTHENTICATOR_SMS_NAME = "AuthySMSAuthenticator";
    public static final String AUTHY_AUTHENTICATOR_PHONE_NAME = "AuthyPhoneAuthenticator";
    public static final String AUTHY_AUTHENTICATOR_ONE_TOUCH_NAME = "AuthyOneTouchAuthenticator";
    public static final String AUTHY_AUTHENTICATOR_APP_TOKEN_NAME = "AuthyAppTokenAuthenticator";

    public static final String AUTHY_SMS_AUTHENTICATOR_FRIENDLY_NAME = "AuthySMS";
    public static final String AUTHY_PHONE_AUTHENTICATOR_FRIENDLY_NAME = "AuthyPhone";
    public static final String AUTHY_ONE_TOUCH_AUTHENTICATOR_FRIENDLY_NAME = "AuthyOneTouch";
    public static final String AUTHY__APP_TOKEN_AUTHENTICATOR_FRIENDLY_NAME = "AuthyAppToken";

    public static final String AUTHY_SEND_TOKEN_URL = "https://api.authy.com/protected/json/";
    public static final String AUTHY_VERIFY_TOKEN_URL = "https://api.authy.com/protected/json/verify/";
    public static final String AUTHY_CREATE_APPROVAL_REQUEST_URL = "https://api.authy.com/onetouch/json/users/";
    public static final String AUTHY_CHECK_APPROVAL_REQUEST_STATUS_URL = "https://api.authy.com/onetouch/json/approval_requests/";

    public static final String AUTHY_APIKEY = "apiKey";
    public static final String AUTHY_APIKEY_PARAM = "?api_key=";
    public static final String AUTHY_FORCE = "&force=true";
    public static final String AUTHY_METHOD_SMS  = "sms";
    public static final String AUTHY_METHOD_CALL  = "call";
    public static final String AUTHY_APPROVAL  = "/approval_requests";
    public static final String AUTHY_MESSAGE_PARAM = "&message=";
    public static final String AUTHY_MESSAGE = "message";
    public static final String AUTHY_LOGO_URL = "logoUrl";
    public static final String AUTHY_LOGO_RESOLUTION = "logoResolution";
    public static final String AUTHY_EXPIRY_TIME = "expiryTime";
    public static final String AUTHY_DENIED = "denied";
    public static final String AUTHY_APPROVED = "approved";
    public static final String AUTHY_SUCCESS = "success";
    public static final String AUTHY_APPROVAL_REQUEST = "approval_request";
    public static final String AUTHY_STATUS = "status";
    public static final String AUTHY_UUID = "uuid";
    public static final String AUTHY_TRUE = "true";
    public static final String AUTHY_TOKEN = "token";
    public static final String AUTHY_IS_VALID= "is valid";
    public static final String AUTHY_ID = "authyId";
    public static final String AUTHY_ID_CLAIM_URI  = "http://wso2.org/claims/authyId";

    public static final String FAILED = "Failed: ";
}