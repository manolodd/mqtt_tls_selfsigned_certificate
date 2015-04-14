package com.enzinatec.mqtt_tls_selfsigned_certificate;

/*
 * ****************************************************************
 *  Copyright (C) 2015 enZina Technologies.
 *
 *  This software is property of enZina Technologies. You are 
 *  granted only the right of using it, but not to modify it 
 *  without the explicit writen permission of enZina Technologies.
 *  For more information contact to enZina technologies at:
 *  - http://www.enzinatec.com 
 *  - info@enzinatec.com
 * ****************************************************************
 */


import java.io.IOException;
import java.io.InputStream;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

/**
 * This class implements a SSL socket factory that uses a TrustManagerFactory to
 * trust the CA certificate of a self-signed MQTT broker certificate. This
 * allows creating a SSL/TLS socket to that MQTT broker avoiding the problem of
 * using an unreliable CA.
 *
 * @author Manuel Domínguez Dorado - ingeniero@ManoloDominguez.com
 * @version 1.0
 */
public class SelfSignedSSLSocketFactory {

    /**
     * This is the constructor of the class. It creates a new instance of
     * SelfSignedSSLSocketFactory and will do the necessary work to initiate
     * attributes and create a SSLSocketFactory as expected.
     *
     * @author Manuel Domínguez Dorado - manuel.dominguez@enzinatec.com
     * @since 1.0
     * @param CAInputStream The InputStream of the file containing the CA
     * certificate that signed the broker's server certificate for TLS.
     * @param hostIPAddressOrDNS Name of the host that is the entry point to the
     * MQTT infrastructure or its corresponding IPv4 address.
     * @param hostPort Port of the entry point to the MQTT infrastructure that
     * is listening for TLS MQTT connections.
     */
    public SelfSignedSSLSocketFactory(InputStream CAInputStream, String hostIPAddressOrDNS, int hostPort) {
        this.CAInputStream = CAInputStream;
        this.hostIPAddressOrDNS = hostIPAddressOrDNS;
        this.hostPort = hostPort;
    }

    /**
     * This method initialize the SelfSignedSSLSocketFactory instance. It reades
     * the CA certificate that signed the MQTT brokers' server certificate and
     * create a TrustManager and KeyStore so that it can be used as a legitimate
     * CA to validate the brokers' server certificate. In this way, a TLS
     * connection can be established to the MQTT infrastructure to cypher
     * communications.
     *
     * @author Manuel Domínguez Dorado - manuel.dominguez@enzinatec.com
     * @since 1.0
     * @throws CertificateException if there is a problem when creating the
     * certificate object from the CA certificate file.
     * @throws IOException if there is a problem accesing the CA certificate
     * file.
     * @throws KeyStoreException if there is a problem when creating the
     * KeyStore to store the CA certificate.
     * @throws NoSuchAlgorithmException if there is a problem with the algorithm
     * selected for the TrustManagerFactory.
     * @throws KeyManagementException if there is a problem with values
     * contained in the CA certificate (expiration...).
     */
    public void initialize() throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException, KeyManagementException {
        // Load CA certificate file from an InputStream. For the context of this
        // project, this certificate correspond to the CA that signed the MQTT 
        // broker certificate. 
        this.certificateFactory = CertificateFactory.getInstance("X.509");
        // A X509 certificate is created from the information stored in CA 
        // certificate file.
        this.untrustedCACertificate = (X509Certificate) this.certificateFactory.generateCertificate(this.CAInputStream);
        this.CAInputStream.close();
        // Create a KeyStore containing the desired CA. This CA will be trusted,
        // but at this moment it is not.
        this.keyStoreType = KeyStore.getDefaultType();
        this.keyStore = KeyStore.getInstance(this.keyStoreType);
        this.keyStore.load(null, null);
        this.keyStore.setCertificateEntry("ca", this.untrustedCACertificate);
        // Create a TrustManager that will trust the CA in our KeyStore. Hence,
        // the CA that has signed the remote MQTT broker certificate will be 
        // reliable.
        this.trustManagerFactoryAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
        this.trustManagerFactory = TrustManagerFactory.getInstance(this.trustManagerFactoryAlgorithm);
        this.trustManagerFactory.init(this.keyStore);
        // Create an SSLContext that uses our TrustManager to generate SSLSocket
        // to connect the remote MQTT broker through TLS.
        this.sslContext = SSLContext.getInstance(SelfSignedSSLSocketFactory.PROTOCOL_TLS);
        this.sslContext.init(null, this.trustManagerFactory.getTrustManagers(), null);
    }

    /**
     * This method returns the SSLSocketFactory. It returns a SSLSocketFactory
     * that will allow a given application to create SSL sockets to the specific
     * MQTT broker whose server certificate has been signed using the CA
     * certificate trusted in this class.
     *
     * @author Manuel Domínguez Dorado - manuel.dominguez@enzinatec.com
     * @since 1.0
     * @return SSLSocketFactory that will allow creating SSLSockets to connect
     * to the specific MQTT broker whose server certificate has been signed
     * using the CA certificate trusted in this class.
     */
    public SSLSocketFactory getSelfSignedSSLSocketFactory() {
        if (this.sslContext != null) {
            return this.sslContext.getSocketFactory();
        }
        return null;
    }

    /**
     * This method returns the complete URL to connect to the MQTT broker whose
     * server certificate has been trusted in this class. It will have the
     * following aspect: ssl://serveraddress:serverport, i.e.
     * ssl://test.mosquitto.org:8883 as needed by the Eclipse PAHO MQTT library.
     *
     * @author Manuel Domínguez Dorado - manuel.dominguez@enzinatec.com
     * @since 1.0
     * @return String. The URL to connect to the MQTT broker whose server
     * certificate has been trusted in this class. Connecting to other untrusted
     * MQTT broker different than those containing a server certificate signed
     * by the specified CA will not be possible using this class.
     */
    public String getMQTTBrokerSecureURL() {
        return "ssl://" + this.hostIPAddressOrDNS + ":" + Integer.toString(this.hostPort);
    }

    private CertificateFactory certificateFactory;
    private InputStream CAInputStream;
    private X509Certificate untrustedCACertificate;
    private String keyStoreType;
    private KeyStore keyStore;
    private String trustManagerFactoryAlgorithm;
    private TrustManagerFactory trustManagerFactory;
    private SSLContext sslContext;
    private String hostIPAddressOrDNS;
    private int hostPort;

    public static final String PROTOCOL_TLS = "TLS";
}
