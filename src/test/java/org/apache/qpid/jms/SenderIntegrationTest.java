/*
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
 */
package org.apache.qpid.jms;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.isA;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.util.Calendar;
import java.util.Date;

import javax.jms.Connection;
import javax.jms.DeliveryMode;
import javax.jms.Message;
import javax.jms.MessageProducer;
import javax.jms.Queue;
import javax.jms.Session;

import org.apache.qpid.jms.impl.DestinationHelper;
import org.apache.qpid.jms.impl.MessageIdHelper;
import org.apache.qpid.jms.test.testpeer.TestAmqpPeer;
import org.apache.qpid.jms.test.testpeer.matchers.sections.MessageAnnotationsSectionMatcher;
import org.apache.qpid.jms.test.testpeer.matchers.sections.MessageHeaderSectionMatcher;
import org.apache.qpid.jms.test.testpeer.matchers.sections.MessagePropertiesSectionMatcher;
import org.apache.qpid.jms.test.testpeer.matchers.sections.TransferPayloadCompositeMatcher;
import org.apache.qpid.jms.test.testpeer.matchers.types.EncodedAmqpValueMatcher;
import org.apache.qpid.proton.amqp.Symbol;
import org.apache.qpid.proton.amqp.UnsignedByte;
import org.apache.qpid.proton.amqp.UnsignedInteger;
import org.junit.Test;

public class SenderIntegrationTest extends QpidJmsTestCase
{
    private final IntegrationTestFixture _testFixture = new IntegrationTestFixture();

    @Test
    public void testDefaultDeliveryModeProducesDurableMessages() throws Exception
    {
        try(TestAmqpPeer testPeer = new TestAmqpPeer(IntegrationTestFixture.PORT);)
        {
            Connection connection = _testFixture.establishConnecton(testPeer);
            testPeer.expectBegin();
            testPeer.expectSenderAttach();

            Session session = connection.createSession(false, Session.AUTO_ACKNOWLEDGE);
            Queue queue = session.createQueue("myQueue");
            MessageProducer producer = session.createProducer(queue);

            //Create and transfer a new message
            MessageHeaderSectionMatcher headersMatcher = new MessageHeaderSectionMatcher(true).withDurable(equalTo(true));
            MessageAnnotationsSectionMatcher msgAnnotationsMatcher = new MessageAnnotationsSectionMatcher(true);
            TransferPayloadCompositeMatcher messageMatcher = new TransferPayloadCompositeMatcher();
            messageMatcher.setHeadersMatcher(headersMatcher);
            messageMatcher.setMessageAnnotationsMatcher(msgAnnotationsMatcher);
            testPeer.expectTransfer(messageMatcher);

            Message message = session.createTextMessage();
            assertEquals(DeliveryMode.PERSISTENT, message.getJMSDeliveryMode());

            producer.send(message);
            assertEquals(DeliveryMode.PERSISTENT, message.getJMSDeliveryMode());
        }
    }

    @Test
    public void testProducerOverridesMessageDeliveryMode() throws Exception
    {
        try(TestAmqpPeer testPeer = new TestAmqpPeer(IntegrationTestFixture.PORT);)
        {
            Connection connection = _testFixture.establishConnecton(testPeer);
            testPeer.expectBegin();
            testPeer.expectSenderAttach();

            Session session = connection.createSession(false, Session.AUTO_ACKNOWLEDGE);
            Queue queue = session.createQueue("myQueue");
            MessageProducer producer = session.createProducer(queue);

            //Create and transfer a new message, explicitly setting the deliveryMode on the
            //message (which applications shouldn't) to NON_PERSISTENT and sending it to check
            //that the producer ignores this value and sends the message as PERSISTENT(/durable)
            MessageHeaderSectionMatcher headersMatcher = new MessageHeaderSectionMatcher(true).withDurable(equalTo(true));
            MessageAnnotationsSectionMatcher msgAnnotationsMatcher = new MessageAnnotationsSectionMatcher(true);
            TransferPayloadCompositeMatcher messageMatcher = new TransferPayloadCompositeMatcher();
            messageMatcher.setHeadersMatcher(headersMatcher);
            messageMatcher.setMessageAnnotationsMatcher(msgAnnotationsMatcher);
            testPeer.expectTransfer(messageMatcher);

            Message message = session.createTextMessage();
            message.setJMSDeliveryMode(DeliveryMode.NON_PERSISTENT);
            assertEquals(DeliveryMode.NON_PERSISTENT, message.getJMSDeliveryMode());

            producer.send(message);

            assertEquals(DeliveryMode.PERSISTENT, message.getJMSDeliveryMode());
        }
    }

    @Test
    public void testSendingMessageSetsJMSDestination() throws Exception
    {
        try(TestAmqpPeer testPeer = new TestAmqpPeer(IntegrationTestFixture.PORT);)
        {
            Connection connection = _testFixture.establishConnecton(testPeer);
            testPeer.expectBegin();
            testPeer.expectSenderAttach();

            Session session = connection.createSession(false, Session.AUTO_ACKNOWLEDGE);
            String queueName = "myQueue";
            Queue queue = session.createQueue(queueName);
            MessageProducer producer = session.createProducer(queue);

            String text = "myMessage";
            MessageHeaderSectionMatcher headersMatcher = new MessageHeaderSectionMatcher(true).withDurable(equalTo(true));
            MessageAnnotationsSectionMatcher msgAnnotationsMatcher = new MessageAnnotationsSectionMatcher(true).withEntry(Symbol.valueOf(DestinationHelper.TO_TYPE_MSG_ANNOTATION_SYMBOL_NAME), equalTo(DestinationHelper.QUEUE_ATTRIBUTES_STRING));
            MessagePropertiesSectionMatcher propsMatcher = new MessagePropertiesSectionMatcher(true).withTo(equalTo(queueName));
            TransferPayloadCompositeMatcher messageMatcher = new TransferPayloadCompositeMatcher();
            messageMatcher.setHeadersMatcher(headersMatcher);
            messageMatcher.setMessageAnnotationsMatcher(msgAnnotationsMatcher);
            messageMatcher.setPropertiesMatcher(propsMatcher);
            messageMatcher.setMessageContentMatcher(new EncodedAmqpValueMatcher(text));
            testPeer.expectTransfer(messageMatcher);

            Message message = session.createTextMessage(text);

            producer.send(message);
        }
    }

    @Test
    public void testSendingMessageSetsJMSTimestamp() throws Exception
    {
        try(TestAmqpPeer testPeer = new TestAmqpPeer(IntegrationTestFixture.PORT);)
        {
            Connection connection = _testFixture.establishConnecton(testPeer);
            testPeer.expectBegin();
            testPeer.expectSenderAttach();

            Session session = connection.createSession(false, Session.AUTO_ACKNOWLEDGE);
            String queueName = "myQueue";
            Queue queue = session.createQueue(queueName);
            MessageProducer producer = session.createProducer(queue);

            Date currentTime = Calendar.getInstance().getTime();
            String text = "myMessage";
            MessageHeaderSectionMatcher headersMatcher = new MessageHeaderSectionMatcher(true).withDurable(equalTo(true));
            MessageAnnotationsSectionMatcher msgAnnotationsMatcher = new MessageAnnotationsSectionMatcher(true);
            MessagePropertiesSectionMatcher propsMatcher = new MessagePropertiesSectionMatcher(true).withCreationTime(greaterThanOrEqualTo(currentTime));
            TransferPayloadCompositeMatcher messageMatcher = new TransferPayloadCompositeMatcher();
            messageMatcher.setHeadersMatcher(headersMatcher);
            messageMatcher.setMessageAnnotationsMatcher(msgAnnotationsMatcher);
            messageMatcher.setPropertiesMatcher(propsMatcher);
            messageMatcher.setMessageContentMatcher(new EncodedAmqpValueMatcher(text));
            testPeer.expectTransfer(messageMatcher);

            Message message = session.createTextMessage(text);

            producer.send(message);
        }
    }

    @Test
    public void testSendingMessageSetsJMSExpirationRelatedAbsoluteExpiryAndTtlFields() throws Exception
    {
        try(TestAmqpPeer testPeer = new TestAmqpPeer(IntegrationTestFixture.PORT);)
        {
            Connection connection = _testFixture.establishConnecton(testPeer);
            testPeer.expectBegin();
            testPeer.expectSenderAttach();

            Session session = connection.createSession(false, Session.AUTO_ACKNOWLEDGE);
            String queueName = "myQueue";
            Queue queue = session.createQueue(queueName);
            MessageProducer producer = session.createProducer(queue);

            long currentTime = System.currentTimeMillis();
            long ttl = 100_000;
            Date expiration = new Date(currentTime + ttl);

            String text = "myMessage";
            MessageHeaderSectionMatcher headersMatcher = new MessageHeaderSectionMatcher(true);
            headersMatcher.withDurable(equalTo(true));
            headersMatcher.withTtl(equalTo(UnsignedInteger.valueOf(ttl)));
            MessageAnnotationsSectionMatcher msgAnnotationsMatcher = new MessageAnnotationsSectionMatcher(true);
            MessagePropertiesSectionMatcher propsMatcher = new MessagePropertiesSectionMatcher(true).withAbsoluteExpiryTime(greaterThanOrEqualTo(expiration));
            TransferPayloadCompositeMatcher messageMatcher = new TransferPayloadCompositeMatcher();
            messageMatcher.setHeadersMatcher(headersMatcher);
            messageMatcher.setMessageAnnotationsMatcher(msgAnnotationsMatcher);
            messageMatcher.setPropertiesMatcher(propsMatcher);
            messageMatcher.setMessageContentMatcher(new EncodedAmqpValueMatcher(text));
            testPeer.expectTransfer(messageMatcher);

            Message message = session.createTextMessage(text);

            producer.send(message, Message.DEFAULT_DELIVERY_MODE, Message.DEFAULT_PRIORITY, ttl);
        }
    }

    /**
     * Test that when a message is sent with default priority of 4, the emitted AMQP message
     * has no value in the header priority field, since the default for that field is already 4.
     */
    @Test
    public void testDefaultPriorityProducesMessagesWithoutPriorityField() throws Exception
    {
        try(TestAmqpPeer testPeer = new TestAmqpPeer(IntegrationTestFixture.PORT);)
        {
            Connection connection = _testFixture.establishConnecton(testPeer);
            testPeer.expectBegin();
            testPeer.expectSenderAttach();

            Session session = connection.createSession(false, Session.AUTO_ACKNOWLEDGE);
            Queue queue = session.createQueue("myQueue");
            MessageProducer producer = session.createProducer(queue);

            //Create and transfer a new message
            MessageHeaderSectionMatcher headersMatcher = new MessageHeaderSectionMatcher(true).withPriority(equalTo(null));
            MessageAnnotationsSectionMatcher msgAnnotationsMatcher = new MessageAnnotationsSectionMatcher(true);
            TransferPayloadCompositeMatcher messageMatcher = new TransferPayloadCompositeMatcher();
            messageMatcher.setHeadersMatcher(headersMatcher);
            messageMatcher.setMessageAnnotationsMatcher(msgAnnotationsMatcher);
            testPeer.expectTransfer(messageMatcher);

            Message message = session.createTextMessage();

            assertEquals(Message.DEFAULT_PRIORITY, message.getJMSPriority());

            producer.send(message);

            assertEquals(Message.DEFAULT_PRIORITY, message.getJMSPriority());
        }
    }

    /**
     * Test that when a message is sent with a non-default priority, the emitted AMQP message
     * has that value in the header priority field, and the JMS message has had JMSPriority set.
     */
    @Test
    public void testNonDefaultPriorityProducesMessagesWithPriorityFieldAndSetsJMSPriority() throws Exception
    {
        try(TestAmqpPeer testPeer = new TestAmqpPeer(IntegrationTestFixture.PORT);)
        {
            Connection connection = _testFixture.establishConnecton(testPeer);
            testPeer.expectBegin();
            testPeer.expectSenderAttach();

            Session session = connection.createSession(false, Session.AUTO_ACKNOWLEDGE);
            Queue queue = session.createQueue("myQueue");
            MessageProducer producer = session.createProducer(queue);

            byte priority = 5;

            //Create and transfer a new message
            MessageHeaderSectionMatcher headersMatcher = new MessageHeaderSectionMatcher(true).withPriority(equalTo(UnsignedByte.valueOf(priority)));
            MessageAnnotationsSectionMatcher msgAnnotationsMatcher = new MessageAnnotationsSectionMatcher(true);
            TransferPayloadCompositeMatcher messageMatcher = new TransferPayloadCompositeMatcher();
            messageMatcher.setHeadersMatcher(headersMatcher);
            messageMatcher.setMessageAnnotationsMatcher(msgAnnotationsMatcher);
            testPeer.expectTransfer(messageMatcher);

            Message message = session.createTextMessage();

            assertEquals(Message.DEFAULT_PRIORITY, message.getJMSPriority());

            producer.send(message, DeliveryMode.PERSISTENT, priority, Message.DEFAULT_TIME_TO_LIVE);

            assertEquals(priority, message.getJMSPriority());
        }
    }

    /**
     * Test that upon sending a message, the sender sets the JMSMessageID on the
     * Message object, and that the expected value is included in the AMQP
     * message sent by the client
     */
    @Test
    public void testSendingMessageSetsJMSMessageID() throws Exception
    {
        try(TestAmqpPeer testPeer = new TestAmqpPeer(IntegrationTestFixture.PORT);)
        {
            Connection connection = _testFixture.establishConnecton(testPeer);
            testPeer.expectBegin();
            testPeer.expectSenderAttach();

            Session session = connection.createSession(false, Session.AUTO_ACKNOWLEDGE);
            String queueName = "myQueue";
            Queue queue = session.createQueue(queueName);
            MessageProducer producer = session.createProducer(queue);

            String text = "myMessage";
            MessageHeaderSectionMatcher headersMatcher = new MessageHeaderSectionMatcher(true).withDurable(equalTo(true));
            MessageAnnotationsSectionMatcher msgAnnotationsMatcher = new MessageAnnotationsSectionMatcher(true);
            MessagePropertiesSectionMatcher propsMatcher = new MessagePropertiesSectionMatcher(true).withMessageId(isA(String.class));
            TransferPayloadCompositeMatcher messageMatcher = new TransferPayloadCompositeMatcher();
            messageMatcher.setHeadersMatcher(headersMatcher);
            messageMatcher.setMessageAnnotationsMatcher(msgAnnotationsMatcher);
            messageMatcher.setPropertiesMatcher(propsMatcher);
            messageMatcher.setMessageContentMatcher(new EncodedAmqpValueMatcher(text));
            testPeer.expectTransfer(messageMatcher);

            Message message = session.createTextMessage(text);


            assertNull("JMSMessageID should not yet be set", message.getJMSMessageID());

            producer.send(message);

            String jmsMessageID = message.getJMSMessageID();
            assertNotNull("JMSMessageID should not yet be set", jmsMessageID);

            //Get the value that was actually transmitted/received, compare to what we have
            testPeer.waitForAllHandlersToComplete(1000);
            Object receivedMessageId = propsMatcher.getReceivedMessageId();
            MessageIdHelper mih = new MessageIdHelper();
            assertEquals("Unexpected AMQP message-id value", mih.stripMessageIdPrefix(jmsMessageID), receivedMessageId);
        }
    }
}
