/*
 * Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *   WSO2 Inc. licenses this file to you under the Apache License,
 *   Version 2.0 (the "License"); you may not use this file except
 *   in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package org.wso2.carbon.inbound.datasift.poll;

import com.datasift.client.DataSiftClient;
import com.datasift.client.DataSiftConfig;
import com.datasift.client.core.Stream;
import com.datasift.client.stream.*;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.synapse.SynapseException;
import org.apache.synapse.core.SynapseEnvironment;
import org.wso2.carbon.inbound.endpoint.protocol.generic.GenericPollingConsumer;

import java.util.Properties;

/**
 * Datasift streaming api Inbound
 */
public class DatasiftStreamData extends GenericPollingConsumer {

    private static final Log log = LogFactory.getLog(DatasiftStreamData.class);

    // Mandatory parameters

    protected static String loginEndpoint;
    private static String userName;
    private static String apiKey;
    private static String csdl;

    private String injectingSeq;
    

    public DatasiftStreamData(Properties datasiftProperties, String name,
                              SynapseEnvironment synapseEnvironment, long scanInterval,
                              String injectingSeq, String onErrorSeq, boolean coordination,
                              boolean sequential) {
        super(datasiftProperties, name, synapseEnvironment, scanInterval,
                injectingSeq, onErrorSeq, coordination, sequential);
        log.info("Initialized the Datasift Streaming consumer");
        loadMandatoryParameters(datasiftProperties);

        this.injectingSeq = injectingSeq;

        // Establishing connection with Datasift streaming api

        DataSiftConfig config = new DataSiftConfig("kesan", "90182285a8bab4ddca3473212d08d7d1");
        log.info("Initialized the config");
        DataSiftClient datasift = new DataSiftClient(config);
        log.info("Initialized the client");

        try {

            // Compile filter looking for mentions of brands
            //String csdl = "interaction.content contains_any \"Calvin Klein, GQ, Love, Adidas\"";
            //String csdl ="interaction.type == \"wikipedia\" and interaction.content contains_any \"a, big, small, fast, slow\"";
            String csdl ="interaction.content contains_any \" small\"";
            Stream stream = datasift.compile(csdl).sync();

            datasift.liveStream().onError(new ErrorHandler()); // handles stream errors
            datasift.liveStream().onStreamEvent(new DeleteHandler()); // handles data deletes

            // Subscribe to the stream
            datasift.liveStream().subscribe(new Subscription(stream));
        } catch (Exception ex) {
            // TODO: Your exception handling here
            System.out.println("Exception:\n " + ex);
        }
    }

    // Subscription handler
    public class Subscription extends StreamSubscription {
        public Subscription(Stream stream) {
            super(stream);
        }

        public void onDataSiftLogMessage(DataSiftMessage di) {
            System.out.println((di.isError() ? "Error" : di.isInfo() ? "Info" : "Warning") + ":\n" + di);
        }

        public void onMessage(Interaction i) {
            System.out.println("INTERACTION:\n" + i);
            injectDatasiftMessage(i);
        }
    }

    // Delete handler
    public static class DeleteHandler extends StreamEventListener {
        public void onDelete(DeletedInteraction di) {
            // You must delete the interaction to stay compliant
            System.out.println("DELETED:\n " + di);
        }
    }

    // Error handler
    public static class ErrorHandler extends ErrorListener {
        public void exceptionCaught(Throwable t) {
            t.printStackTrace();
            // TODO: do something useful..!
        }
    }
    /**
     * load  properties for Datasift inbound endpoint
     *
     * @param properties
     */
    private void loadMandatoryParameters(Properties properties) {
        if (log.isDebugEnabled()) {
            log.debug("Starting to load the Datasift credentials");
        }

        userName = properties.getProperty(DatasiftConstants.USER_NAME);
        apiKey = properties.getProperty(DatasiftConstants.APIKEY);
        csdl = properties.getProperty(DatasiftConstants.CSDL);


//        if (log.isDebugEnabled()) {
            log.info("Loaded the Datasift userName : " + userName
                    + ",password : "  + ",LoginEndpoint : "
                    + loginEndpoint + "securityToken" + "Loading the object"
                    );
        //}
    }


    public Object poll() {
        return null;
    }

    /**
     * Injecting the Datasift Stream messages to the ESB sequence
     *
     * @param message the Datasift response status
     */
    public void injectDatasiftMessage(Interaction message) {
        if (injectingSeq != null) {
            injectMessage(message.toString(), DatasiftConstants.CONTENT_TYPE);
            if (log.isDebugEnabled()) {
                log.debug("injecting Datasift message to the sequence : "
                        + injectingSeq);
            }
        } else {
            handleException("the Sequence is not found");
        }
    }

    private void handleException(String msg, Exception ex) {
        log.error(msg, ex);
        throw new SynapseException(ex);
    }

    private void handleException(String msg) {
        log.error(msg);
        throw new SynapseException(msg);
    }

}
