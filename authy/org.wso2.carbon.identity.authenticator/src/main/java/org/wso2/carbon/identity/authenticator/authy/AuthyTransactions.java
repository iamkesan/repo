package org.wso2.carbon.identity.authenticator.authy;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.net.ssl.HttpsURLConnection;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;

/**
 * Created by kesavan on 10/22/15.
 */
public class AuthyTransactions {

    private static Log log = LogFactory.getLog(AuthyTransactions.class);

    public String sendToken(String method, String authyId, String apiKey){

        String url=AuthyConstants.AUTHY_SEND_TOKEN_URL+method+"/"+authyId+AuthyConstants.AUTHY_APIKEY_PARAM+apiKey+AuthyConstants.AUTHY_FORCE;
        //String url="https://api.authy.com/protected/json/sms/8632251?api_key=aAsm0CbF0GJGFVzR5PMc7yZqo9Hi7ah4&force=true";
        log.info(url);
        String responseString = "";

        try {
            HttpsURLConnection connection = (HttpsURLConnection) new URL(url).openConnection();

            int status = connection.getResponseCode();
            log.info("AUTHY Response Code22222222 :" + status);

            if (log.isDebugEnabled()) {
                log.debug("AUTHY Response Code :" + status);
            }

            BufferedReader br = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) {
                sb.append(line).append("\n");
            }
            br.close();
            responseString = sb.toString();
            log.debug("AUTHY Response :" + responseString);

        } catch (IOException e) {
            e.printStackTrace();
        }

        return responseString;
    }

    public String verifyToken(String token, String authyId, String apiKey){
        String url =AuthyConstants.AUTHY_VERIFY_TOKEN_URL+token+"/"+authyId+AuthyConstants.AUTHY_APIKEY_PARAM+apiKey;
       // String url = "https://api.authy.com/protected/json/verify/" + token + "/8632251?api_key=aAsm0CbF0GJGFVzR5PMc7yZqo9Hi7ah4";
        String responseString = "";
        log.info("AUTHY Response1111111 :" + responseString);
        try {
            HttpsURLConnection connection = (HttpsURLConnection) new URL(url).openConnection();

            int status = connection.getResponseCode();
            log.info("AUTHY Response Code22222222 :" + status);

            if (log.isDebugEnabled()) {
                log.debug("AUTHY Response Code22222222 :" + status);
            }
            log.info("AUTHY Response222222211 :" + responseString);
            BufferedReader br = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) {
                sb.append(line).append("\n");
            }
            br.close();
            responseString = sb.toString();
            log.info("AUTHY Response3333333 :" + responseString);

        } catch (IOException e) {
            log.info(e.getMessage());
        }

        return responseString;
    }

    public String createApprovalRequest(String authyId, String apiKey, String message, String logoUrl, String logoResolution){
String method="sms";
       // String url=AuthyConstants.AUTHY_CREATE_APPROVAL_REQUEST_URL+authyId+"/"+AuthyConstants.AUTHY_APPROVAL+AuthyConstants.AUTHY_APIKEY_PARAM+apiKey+AuthyConstants.AUTHY_MESSAGE_PARAM+message;
        //String url="https://api.authy.com/protected/json/sms/8632251?api_key=aAsm0CbF0GJGFVzR5PMc7yZqo9Hi7ah4&force=true";
        //String url ="https://api.authy.com/onetouch/json/users/8632251/approval_requests?api_key=aAsm0CbF0GJGFVzR5PMc7yZqo9Hi7ah4&message=Hi&details[username]=Bill Smith&logos[][url]=https://upload.wikimedia.org/wikipedia/commons/thumb/1/11/Flag_of_Sri_Lanka.svg/2000px-Flag_of_Sri_Lanka.svg.png&logos[][res]=default";
        String url=AuthyConstants.AUTHY_CREATE_APPROVAL_REQUEST_URL+authyId+AuthyConstants.AUTHY_APPROVAL+AuthyConstants.AUTHY_APIKEY_PARAM+apiKey+AuthyConstants.AUTHY_MESSAGE_PARAM+message;
        log.info(url);
        String responseString = "";

        try {
            HttpsURLConnection connection = (HttpsURLConnection) new URL(url).openConnection();
            connection.setRequestMethod("POST");
            int status = connection.getResponseCode();
            log.info("AUTHY Response Code22222222 :" + status);

            if (log.isDebugEnabled()) {
                log.debug("AUTHY Response Code :" + status);
            }

            BufferedReader br = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) {
                sb.append(line).append("\n");
            }
            br.close();
            responseString = sb.toString();
            log.debug("AUTHY Response :" + responseString);
            log.info("AUTHY Response222222211 :" + responseString);
        } catch (IOException e) {
            e.printStackTrace();
        }

        return responseString;
    }

    public String checkApprovalRequestStatus(String uuid, String apiKey){
        String url =AuthyConstants.AUTHY_CHECK_APPROVAL_REQUEST_STATUS_URL+uuid+AuthyConstants.AUTHY_APIKEY_PARAM+apiKey;
        // String url = "https://api.authy.com/protected/json/verify/" + token + "/8632251?api_key=aAsm0CbF0GJGFVzR5PMc7yZqo9Hi7ah4";

        String responseString = "";
        log.info("AUTHY Response1111111 :" + responseString);
        try {
            HttpsURLConnection connection = (HttpsURLConnection) new URL(url).openConnection();

            int status = connection.getResponseCode();
            log.info("AUTHY Response Code22222222 :" + status);

            if (log.isDebugEnabled()) {
                log.debug("AUTHY Response Code22222222 :" + status);
            }
            log.info("AUTHY Response222222211 :" + responseString);
            BufferedReader br = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) {
                sb.append(line).append("\n");
            }
            br.close();
            responseString = sb.toString();
            log.info("AUTHY Response3333333 :" + responseString);

        } catch (IOException e) {
            log.info(e.getMessage());
        }

        return responseString;
    }

}
