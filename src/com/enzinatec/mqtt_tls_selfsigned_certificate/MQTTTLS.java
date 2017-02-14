/* 
 * Copyright 2015 (C) enZina Technologies
 * manuel.dominguez@enzinatec.com
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.enzinatec.mqtt_tls_selfsigned_certificate;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.eclipse.paho.client.mqttv3.IMqttToken;
import org.eclipse.paho.client.mqttv3.MqttAsyncClient;
import org.eclipse.paho.client.mqttv3.MqttConnectOptions;
import org.eclipse.paho.client.mqttv3.MqttException;

/**
 *
 * @author Manuel Domínguez-Dorado - manuel.dominguez@enzinatec.com
 * @version
 */
public class MQTTTLS {

    public MQTTTLS() {
        try {
            InputStream caInputStream = getClass().getResourceAsStream("/com/enzinatec/mqtt_tls_selfsigned_certificate/mosquitto.org.crt");
            SelfSignedSSLSocketFactory socketFactory = new SelfSignedSSLSocketFactory(caInputStream, "test.mosquitto.org", 8883);
            socketFactory.initialize();
            
            MqttConnectOptions options = new MqttConnectOptions();
            options.setSocketFactory(socketFactory.getSelfSignedSSLSocketFactory());
            
            MqttAsyncClient client = new MqttAsyncClient(socketFactory.getMQTTBrokerSecureURL(), MqttAsyncClient.generateClientId(), null);
            IMqttToken connectToken = client.connect(options);
            connectToken.waitForCompletion();
            System.out.println("Connected to the remote broker");   
            System.out.println("Disconnecting before shutting down...");   
            IMqttToken disconnectToken = client.disconnect();
            disconnectToken.waitForCompletion();
            System.out.println("Disconnected from the remote broker");   
        } catch (MqttException ex) {
            Logger.getLogger(MQTTTLS.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertificateException ex) {
            Logger.getLogger(MQTTTLS.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(MQTTTLS.class.getName()).log(Level.SEVERE, null, ex);
        } catch (KeyStoreException ex) {
            Logger.getLogger(MQTTTLS.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(MQTTTLS.class.getName()).log(Level.SEVERE, null, ex);
        } catch (KeyManagementException ex) {
            Logger.getLogger(MQTTTLS.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

}
