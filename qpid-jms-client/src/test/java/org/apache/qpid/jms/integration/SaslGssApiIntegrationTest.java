/*
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 */
package org.apache.qpid.jms.integration;

import org.apache.hadoop.minikdc.MiniKdc;
import org.apache.qpid.jms.JmsConnectionFactory;
import org.apache.qpid.jms.test.QpidJmsTestCase;
import org.apache.qpid.jms.test.testpeer.TestAmqpPeer;
import org.apache.qpid.proton.amqp.Symbol;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import javax.jms.Connection;
import javax.jms.ConnectionFactory;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.Assert.assertNull;

public class SaslGssApiIntegrationTest extends QpidJmsTestCase {

    private static final Symbol GSSKRB5 = Symbol.valueOf("GSSAPI");

    private MiniKdc kdc;

    @Before
    public void setUpKerberso() throws Exception {
        Path tempDirectory = Files.createTempDirectory("junit.test.");
        File root = tempDirectory.toFile();
        root.deleteOnExit();
        kdc = new MiniKdc(MiniKdc.createConf(), new File(root, "kdc"));
        kdc.start();

        // hard coded match, default_keytab_name in minikdc-krb5.conf template
        File userKeyTab = new File("target/test.krb5.keytab");
        kdc.createPrincipal(userKeyTab, "client", "host/localhost");
    }

    @After
    public void stopKDC() throws Exception {
        if (kdc != null) {
            kdc.stop();
        }
    }

    @Test(timeout = 20000)
    public void testSaslGssApiKrbConnection() throws Exception {
        try (TestAmqpPeer testPeer = new TestAmqpPeer();) {

            testPeer.expectGSSAPI(GSSKRB5);
            testPeer.expectOpen();

            // Each connection creates a session for managing temporary destinations etc
            testPeer.expectBegin();

            String uriOptions = "?amqp.saslLayer=true&amqp.saslMechanisms=" + GSSKRB5.toString();
            ConnectionFactory factory = new JmsConnectionFactory("amqp://localhost:" + testPeer.getServerPort() + uriOptions);
            Connection connection = factory.createConnection("client", null);
            // Set a clientID to provoke the actual AMQP connection process to occur.
            connection.setClientID("clientName");

            testPeer.waitForAllHandlersToComplete(1000);
            assertNull(testPeer.getThrowable());

            testPeer.expectClose();
            connection.close();
        }
    }

}
