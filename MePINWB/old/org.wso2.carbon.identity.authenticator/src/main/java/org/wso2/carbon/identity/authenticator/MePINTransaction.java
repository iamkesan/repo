package org.wso2.carbon.identity.authenticator;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;

import javax.net.ssl.HttpsURLConnection;
import java.io.*;
import java.net.URL;
import java.net.URLEncoder;

public class MePINTransaction {

    private static Log log = LogFactory.getLog(MePINTransaction.class);

    protected JsonObject createTransaction(String mepinID, String sessionID, String url, String username,
                                           String password, String clientId, String header, String message, String shortMessage,
                                           String confirmationPolicy, String callbackUrl, String expiryTime) throws IOException {

        log.debug("Started handling transaction creation");

        String query = String.format(MePINConstants.MEPIN_QUERY,
                URLEncoder.encode(sessionID, MePINConstants.CHARSET),
                URLEncoder.encode(shortMessage, MePINConstants.CHARSET),
                URLEncoder.encode(header, MePINConstants.CHARSET),
                URLEncoder.encode(message, MePINConstants.CHARSET),
                URLEncoder.encode(clientId, MePINConstants.CHARSET),
                URLEncoder.encode(mepinID, MePINConstants.CHARSET),
                URLEncoder.encode(expiryTime, MePINConstants.CHARSET),
                URLEncoder.encode(callbackUrl, MePINConstants.CHARSET),
                URLEncoder.encode(confirmationPolicy, MePINConstants.CHARSET)
        );

        String response = postRequest(url, query, username, password);

        JsonObject responseJson = new JsonParser().parse(response).getAsJsonObject();
        if (log.isDebugEnabled()) {
            log.debug("MePin JSON Response: " + responseJson);
        }
        return responseJson;
    }

    private String postRequest(String url, String query, String username, String password) throws IOException {

        String authStr = username + ":" + password;
        String encoding = new String(Base64.encodeBase64(authStr.getBytes()));
        String responseString = "";
        HttpsURLConnection connection = null;

        try {
            connection = (HttpsURLConnection) new URL(url).openConnection();
            connection.setDoOutput(true);
            connection.setRequestProperty(MePINConstants.HTTP_ACCEPT_CHARSET, MePINConstants.CHARSET);
            connection.setRequestProperty(MePINConstants.HTTP_CONTENT_TYPE, MePINConstants.HTTP_POST_CONTENT_TYPE);
            connection.setRequestProperty(MePINConstants.HTTP_AUTHORIZATION, MePINConstants.HTTP_AUTHORIZATION_BASIC + encoding);

            OutputStream output = connection.getOutputStream();
            output.write(query.getBytes(MePINConstants.CHARSET));

            int status = connection.getResponseCode();

            if (log.isDebugEnabled()) {
                log.debug("MePIN Response Code :" + status);
            }

            switch (status) {
                case 200:
                case 201:
                case 400:
                case 403:
                case 404:
                case 500:
                    BufferedReader br = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                    StringBuilder sb = new StringBuilder();
                    String line;
                    while ((line = br.readLine()) != null) {
                        sb.append(line).append("\n");
                    }
                    br.close();
                    responseString = sb.toString();
                    break;
            }
        } catch (IOException e) {
            if (connection.getErrorStream() != null) {
                BufferedReader br = new BufferedReader(new InputStreamReader(connection.getErrorStream()));
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = br.readLine()) != null) {
                    sb.append(line).append("\n");
                }
                br.close();
                responseString = sb.toString();
            }
        } finally {
            connection.disconnect();
        }
        if (log.isDebugEnabled()) {
            log.debug("MePIN Response :" + responseString);
        }
        return responseString;
    }

    protected JsonObject getTransaction(String url, String transactionId, String clientId, String username,
                                        String password) throws IOException {

        log.debug("Started handling transaction creation");
        String authStr = username + ":" + password;
        String encoding = new String(Base64.encodeBase64(authStr.getBytes()));
        HttpsURLConnection connection = null;
        JsonObject responseJson = null;

        url = url + "?transaction_id=" + transactionId + "&client_id=" + clientId + "";
        try {
            connection = (HttpsURLConnection) new URL(url).openConnection();

            connection.setRequestMethod(MePINConstants.HTTP_GET);
            connection.setRequestProperty(MePINConstants.HTTP_ACCEPT, MePINConstants.HTTP_CONTENT_TYPE);
            connection.setRequestProperty(MePINConstants.HTTP_AUTHORIZATION, MePINConstants.HTTP_AUTHORIZATION_BASIC + encoding);

            String response = "";
            int statusCode = connection.getResponseCode();
            InputStream is;
            if ((statusCode == 200) || (statusCode == 201)) {
                is = connection.getInputStream();
            } else {
                is = connection.getErrorStream();
            }

            BufferedReader br = new BufferedReader(new InputStreamReader(is));
            String output;
            while ((output = br.readLine()) != null) {
                response += output;
            }
            br.close();
            if (log.isDebugEnabled()) {
                log.debug("MePIN Status Response: " + response);
            }

            responseJson = new JsonParser().parse(response).getAsJsonObject();
        } catch (IOException e) {
            throw new IOException(e.getMessage(), e);
        } finally {
            connection.disconnect();//TODO close the buffer readers
        }
        return responseJson;
    }

    public String getUserInformation(String accessToken,String username, String password) throws AuthenticationFailedException {
        String responseString = "";
        //JsonObject responseJson = null;
        HttpsURLConnection connection = null;
        String authStr = username + ":" + password;
        String encoding = new String(Base64.encodeBase64(authStr.getBytes()));

        try {
            String query = String.format("access_token=%s",
                                         URLEncoder.encode(accessToken, MePINConstants.CHARSET));

            connection = (HttpsURLConnection) new URL(MePINConstants.MEPIN_GET_USER_INFO_URL + "?" + query).openConnection();
            connection.setRequestMethod(MePINConstants.HTTP_GET);
            connection.setRequestProperty(MePINConstants.HTTP_ACCEPT, MePINConstants.HTTP_CONTENT_TYPE);
            connection.setRequestProperty(MePINConstants.HTTP_AUTHORIZATION, MePINConstants.HTTP_AUTHORIZATION_BASIC + encoding);
            int status = connection.getResponseCode();
            log.info("MePIN Response Code :" + status);
            if (log.isDebugEnabled()) {
                log.debug("MePIN Response Code :" + status);
            }
            if (status == 200) {
                BufferedReader br = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = br.readLine()) != null) {
                    sb.append(line).append("\n");
                }
                br.close();
                responseString = sb.toString();
                //  responseJson = new JsonParser().parse(responseString).getAsJsonObject();
                if (log.isDebugEnabled()) {
                    log.debug("MePIN Response :" + responseString);
                }
            } else {
                return "failed";
            }

        } catch (IOException e) {
            throw new AuthenticationFailedException(MePINConstants.MEPIN_ID_NOT_FOUND, e);
        } finally {
            connection.disconnect();//TODO close the buffer readers
            //TODO format the logs
        }
        return responseString;
    }

}