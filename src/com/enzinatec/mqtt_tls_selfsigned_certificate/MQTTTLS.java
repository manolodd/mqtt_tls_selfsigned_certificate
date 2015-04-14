/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
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
