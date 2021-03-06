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
package org.apache.qpid.jms.test.testpeer;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

import org.apache.qpid.jms.test.testpeer.describedtypes.Accepted;
import org.apache.qpid.jms.test.testpeer.describedtypes.AttachFrame;
import org.apache.qpid.jms.test.testpeer.describedtypes.BeginFrame;
import org.apache.qpid.jms.test.testpeer.describedtypes.CloseFrame;
import org.apache.qpid.jms.test.testpeer.describedtypes.DispositionFrame;
import org.apache.qpid.jms.test.testpeer.describedtypes.FlowFrame;
import org.apache.qpid.jms.test.testpeer.describedtypes.OpenFrame;
import org.apache.qpid.jms.test.testpeer.describedtypes.SaslMechanismsFrame;
import org.apache.qpid.jms.test.testpeer.describedtypes.SaslOutcomeFrame;
import org.apache.qpid.jms.test.testpeer.describedtypes.TransferFrame;
import org.apache.qpid.jms.test.testpeer.describedtypes.sections.ApplicationPropertiesDescribedType;
import org.apache.qpid.jms.test.testpeer.describedtypes.sections.HeaderDescribedType;
import org.apache.qpid.jms.test.testpeer.describedtypes.sections.MessageAnnotationsDescribedType;
import org.apache.qpid.jms.test.testpeer.describedtypes.sections.PropertiesDescribedType;
import org.apache.qpid.jms.test.testpeer.matchers.AttachMatcher;
import org.apache.qpid.jms.test.testpeer.matchers.BeginMatcher;
import org.apache.qpid.jms.test.testpeer.matchers.CloseMatcher;
import org.apache.qpid.jms.test.testpeer.matchers.DispositionMatcher;
import org.apache.qpid.jms.test.testpeer.matchers.FlowMatcher;
import org.apache.qpid.jms.test.testpeer.matchers.OpenMatcher;
import org.apache.qpid.jms.test.testpeer.matchers.SaslInitMatcher;
import org.apache.qpid.jms.test.testpeer.matchers.TransferMatcher;
import org.apache.qpid.proton.Proton;
import org.apache.qpid.proton.amqp.Binary;
import org.apache.qpid.proton.amqp.DescribedType;
import org.apache.qpid.proton.amqp.Symbol;
import org.apache.qpid.proton.amqp.UnsignedByte;
import org.apache.qpid.proton.amqp.UnsignedInteger;
import org.apache.qpid.proton.amqp.UnsignedShort;
import org.apache.qpid.proton.codec.Data;
import org.apache.qpid.proton.engine.impl.AmqpHeader;
import org.hamcrest.Matcher;
import org.hamcrest.Matchers;
import org.junit.Assert;

// TODO should expectXXXYYYZZZ methods just be expect(matcher)?
public class TestAmqpPeer implements AutoCloseable
{
    private static final Logger _logger = Logger.getLogger(TestAmqpPeer.class.getName());

    /** Roles are represented as booleans - see AMQP spec 2.8.1*/
    private static final boolean SENDER_ROLE = false;

    /** Roles are represented as booleans - see AMQP spec 2.8.1*/
    private static final boolean RECEIVER_ROLE = true;

    private static final UnsignedByte ATTACH_SND_SETTLE_MODE_UNSETTLED = UnsignedByte.valueOf((byte) 0);

    private static final UnsignedByte ATTACH_RCV_SETTLE_MODE_FIRST = UnsignedByte.valueOf((byte)0);

    private final TestAmqpPeerRunner _driverRunnable;
    private final Thread _driverThread;

    /**
     * Guarded by {@link #_handlersLock}
     */
    private final List<Handler> _handlers = new ArrayList<Handler>();
    private final Object _handlersLock = new Object();

    /**
     * Guarded by {@link #_handlersLock}
     */
    private CountDownLatch _handlersCompletedLatch;

    private int _nextLinkHandle = 100;

    public TestAmqpPeer(int port) throws IOException
    {
        _driverRunnable = new TestAmqpPeerRunner(port, this);
        _driverThread = new Thread(_driverRunnable, "MockAmqpPeerThread");
        _driverThread.start();
    }

    /**
     * Shuts down the test peer, throwing any Throwable
     * that occurred on the peer, or validating that no
     * unused matchers remain.
     */
    @Override
    public void close() throws Exception
    {
        _driverRunnable.stop();

        try
        {
            _driverThread.join(30000);
        }
        catch (InterruptedException e)
        {
            Thread.currentThread().interrupt();
        }
        finally
        {
            Throwable throwable = getThrowable();
            if(throwable == null)
            {
                synchronized(_handlersLock)
                {
                    assertThat(_handlers, Matchers.empty());
                }
            }
            else
            {
                //AutoClosable can't handle throwing Throwables, so we wrap it.
                throw new RuntimeException("TestPeer caught throwable during run", throwable);
            }
        }
    }

    public Throwable getThrowable()
    {
        return _driverRunnable.getException();
    }

    public void receiveHeader(byte[] header)
    {
        Handler handler = getFirstHandler();
        if(handler instanceof HeaderHandler)
        {
            ((HeaderHandler)handler).header(header,this);
            if(handler.isComplete())
            {
                removeFirstHandler();
            }
        }
        else
        {
            throw new IllegalStateException("Received header but the next handler is a " + handler);
        }
    }

    public void receiveFrame(int type, int channel, DescribedType describedType, Binary payload)
    {
        Handler handler = getFirstHandler();
        if(handler instanceof FrameHandler)
        {
            ((FrameHandler)handler).frame(type, channel, describedType, payload, this);
            if(handler.isComplete())
            {
                removeFirstHandler();
            }
        }
        else
        {
            throw new IllegalStateException("Received frame but the next handler is a " + handler);
        }
    }

    private void removeFirstHandler()
    {
        synchronized(_handlersLock)
        {
            Handler h = _handlers.remove(0);
            if(_handlersCompletedLatch != null)
            {
                _handlersCompletedLatch.countDown();
            }
            _logger.finest("Removed completed handler: " + h);
        }
    }

    private void addHandler(Handler handler)
    {
        synchronized(_handlersLock)
        {
            _handlers.add(handler);
            _logger.fine("Added handler " + handler);
        }
    }

    private Handler getFirstHandler()
    {
        synchronized(_handlersLock)
        {
            if(_handlers.isEmpty())
            {
                throw new IllegalStateException("No handlers");
            }
            return _handlers.get(0);
        }
    }

    public void waitForAllHandlersToComplete(int timeoutMillis) throws InterruptedException
    {
        synchronized(_handlersLock)
        {
            _handlersCompletedLatch = new CountDownLatch(_handlers.size());
        }

        boolean countedDownOk = _handlersCompletedLatch.await(timeoutMillis, TimeUnit.MILLISECONDS);

        Assert.assertTrue(
                "All handlers should have completed within the " + timeoutMillis + "ms timeout", countedDownOk);
    }

    void sendHeader(byte[] header)
    {
        _logger.fine("About to send header "+ new Binary(header));
        _driverRunnable.sendBytes(header);
    }

    public void sendFrame(FrameType type, int channel, DescribedType describedType, Binary payload)
    {
        _logger.fine("About to send "+ describedType);
        byte[] output = AmqpDataFramer.encodeFrame(type, channel, describedType, payload);
        _driverRunnable.sendBytes(output);
    }

    public void expectPlainConnect(String username, String password, boolean authorize)
    {
        SaslMechanismsFrame saslMechanismsFrame = new SaslMechanismsFrame().setSaslServerMechanisms(Symbol.valueOf("PLAIN"));
        addHandler(new HeaderHandlerImpl(AmqpHeader.SASL_HEADER, AmqpHeader.SASL_HEADER,
                                            new FrameSender(
                                                    this, FrameType.SASL, 0,
                                                    saslMechanismsFrame, null)));

        byte[] usernameBytes = username.getBytes();
        byte[] passwordBytes = password.getBytes();
        byte[] data = new byte[usernameBytes.length+passwordBytes.length+2];
        System.arraycopy(usernameBytes, 0, data, 1, usernameBytes.length);
        System.arraycopy(passwordBytes, 0, data, 2 + usernameBytes.length, passwordBytes.length);

        addHandler(new SaslInitMatcher()
            .withMechanism(equalTo(Symbol.valueOf("PLAIN")))
            .withInitialResponse(equalTo(new Binary(data)))
            .onSuccess(new AmqpPeerRunnable()
            {
                @Override
                public void run()
                {
                    TestAmqpPeer.this.sendFrame(
                            FrameType.SASL, 0,
                            new SaslOutcomeFrame().setCode(UnsignedByte.valueOf((byte)0)),
                            null);
                    _driverRunnable.expectHeader();
                }
            }));

        addHandler(new HeaderHandlerImpl(AmqpHeader.HEADER, AmqpHeader.HEADER));

        addHandler(new OpenMatcher()
            .withContainerId(notNullValue(String.class))
            .onSuccess(new FrameSender(
                    this, FrameType.AMQP, 0,
                    new OpenFrame().setContainerId("test-amqp-peer-container-id"),
                    null)));
    }

    public void expectClose()
    {
        addHandler(new CloseMatcher()
            .withError(Matchers.nullValue())
            .onSuccess(new FrameSender(this, FrameType.AMQP, 0,
                    new CloseFrame(),
                    null)));
    }

    public void expectBegin()
    {
        final BeginMatcher beginMatcher = new BeginMatcher()
                .withRemoteChannel(nullValue())
                .withNextOutgoingId(notNullValue())
                .withIncomingWindow(notNullValue())
                .withOutgoingWindow(notNullValue());

        // the response will have its remote channel dynamically set based on incoming value
        final BeginFrame beginResponse = new BeginFrame()
            .setNextOutgoingId(UnsignedInteger.ZERO)
            .setIncomingWindow(UnsignedInteger.ZERO)
            .setOutgoingWindow(UnsignedInteger.ZERO);

        beginMatcher.onSuccess(
                new FrameSender(this, FrameType.AMQP, 0, beginResponse, null)
                    .setValueProvider(new ValueProvider()
                        {
                            @Override
                            public void setValues()
                            {
                                beginResponse.setRemoteChannel(
                                        UnsignedShort.valueOf((short) beginMatcher.getActualChannel()));
                            }
                        }));

        addHandler(beginMatcher);
    }

    public void expectSenderAttach()
    {
        final AttachMatcher attachMatcher = new AttachMatcher()
                .withName(notNullValue())
                .withHandle(notNullValue())
                .withRole(equalTo(SENDER_ROLE))
                .withSndSettleMode(equalTo(ATTACH_SND_SETTLE_MODE_UNSETTLED))
                .withRcvSettleMode(equalTo(ATTACH_RCV_SETTLE_MODE_FIRST))
                .withSource(notNullValue())
                .withTarget(notNullValue());

        UnsignedInteger linkHandle = UnsignedInteger.valueOf(_nextLinkHandle++);
        final AttachFrame attachResponse = new AttachFrame()
                            .setHandle(linkHandle)
                            .setRole(RECEIVER_ROLE)
                            .setSndSettleMode(ATTACH_SND_SETTLE_MODE_UNSETTLED)
                            .setRcvSettleMode(ATTACH_RCV_SETTLE_MODE_FIRST);

        FrameSender attachResponseSender = new FrameSender(this, FrameType.AMQP, 0, attachResponse, null)
                            .setValueProvider(new ValueProvider()
                            {
                                @Override
                                public void setValues()
                                {
                                    attachResponse.setName(attachMatcher.getReceivedName());
                                    attachResponse.setSource(attachMatcher.getReceivedSource());
                                    attachResponse.setTarget(attachMatcher.getReceivedTarget());
                                }
                            });

        final FlowFrame flowFrame = new FlowFrame().setNextIncomingId(UnsignedInteger.ZERO)
                .setIncomingWindow(UnsignedInteger.valueOf(2048))
                .setNextOutgoingId(UnsignedInteger.ZERO)
                .setOutgoingWindow(UnsignedInteger.valueOf(2048))
                .setLinkCredit(UnsignedInteger.valueOf(100))
                .setHandle(linkHandle);

        FrameSender flowFrameSender = new FrameSender(this, FrameType.AMQP, 0, flowFrame, null)
                            .setValueProvider(new ValueProvider()
                            {
                                @Override
                                public void setValues()
                                {
                                    flowFrame.setDeliveryCount(attachMatcher.getReceivedInitialDeliveryCount());
                                }
                            });

        CompositeAmqpPeerRunnable composite = new CompositeAmqpPeerRunnable();
        composite.add(attachResponseSender);
        composite.add(flowFrameSender);

        attachMatcher.onSuccess(composite);

        addHandler(attachMatcher);
    }

    public void expectReceiverAttach()
    {
        final AttachMatcher attachMatcher = new AttachMatcher()
                .withName(notNullValue())
                .withHandle(notNullValue())
                .withRole(equalTo(RECEIVER_ROLE))
                .withSndSettleMode(equalTo(ATTACH_SND_SETTLE_MODE_UNSETTLED))
                .withRcvSettleMode(equalTo(ATTACH_RCV_SETTLE_MODE_FIRST))
                .withSource(notNullValue())
                .withTarget(notNullValue());

        UnsignedInteger linkHandle = UnsignedInteger.valueOf(_nextLinkHandle++);
        final AttachFrame attachResponse = new AttachFrame()
                            .setHandle(linkHandle)
                            .setRole(SENDER_ROLE)
                            .setSndSettleMode(ATTACH_SND_SETTLE_MODE_UNSETTLED)
                            .setRcvSettleMode(ATTACH_RCV_SETTLE_MODE_FIRST)
                            .setInitialDeliveryCount(UnsignedInteger.ZERO);

        FrameSender attachResponseSender = new FrameSender(this, FrameType.AMQP, 0, attachResponse, null)
                            .setValueProvider(new ValueProvider()
                            {
                                @Override
                                public void setValues()
                                {
                                    attachResponse.setName(attachMatcher.getReceivedName());
                                    attachResponse.setSource(attachMatcher.getReceivedSource());
                                    attachResponse.setTarget(attachMatcher.getReceivedTarget());
                                }
                            });

        attachMatcher.onSuccess(attachResponseSender);

        addHandler(attachMatcher);
    }

    public void expectLinkFlowRespondWithTransfer(final HeaderDescribedType headerDescribedType,
                                                  final MessageAnnotationsDescribedType messageAnnotationsDescribedType,
                                                  final PropertiesDescribedType propertiesDescribedType,
                                                  final ApplicationPropertiesDescribedType appPropertiesDescribedType,
                                                  final DescribedType content)
    {
        final FlowMatcher flowMatcher = new FlowMatcher()
                        .withLinkCredit(Matchers.greaterThan(UnsignedInteger.ZERO));

        final TransferFrame transferResponse = new TransferFrame()
            .setHandle(UnsignedInteger.valueOf(_nextLinkHandle - 1)) // TODO: this needs to be the value used in the attach response
            .setDeliveryId(UnsignedInteger.ZERO) // TODO: we shouldn't assume this is the first transfer on the session
            .setDeliveryTag(new Binary("theDeliveryTag".getBytes()))
            .setMessageFormat(UnsignedInteger.ZERO)
            .setSettled(false);

        Data payloadData = Proton.data(1024);

        if(headerDescribedType != null)
        {
            payloadData.putDescribedType(headerDescribedType);
        }

        if(messageAnnotationsDescribedType != null)
        {
            payloadData.putDescribedType(messageAnnotationsDescribedType);
        }

        if(propertiesDescribedType != null)
        {
            payloadData.putDescribedType(propertiesDescribedType);
        }

        if(appPropertiesDescribedType != null)
        {
            payloadData.putDescribedType(appPropertiesDescribedType);
        }

        if(content != null)
        {
            payloadData.putDescribedType(content);
        }

        Binary payload = payloadData.encode();

        FrameSender transferResponseSender = new FrameSender(
                this,
                FrameType.AMQP,
                0, // TODO use correct channel number (and check for dodgy hard-coded zeros elsewhere)
                transferResponse,
                payload);

        flowMatcher.onSuccess(transferResponseSender);

        addHandler(flowMatcher);
    }

    public void expectTransfer(Matcher<Binary> expectedPayloadMatcher)
    {
        final TransferMatcher transferMatcher = new TransferMatcher();
        transferMatcher.setPayloadMatcher(expectedPayloadMatcher);

        final DispositionFrame dispositionFrame = new DispositionFrame()
                                                   .setRole(RECEIVER_ROLE)
                                                   .setSettled(true)
                                                   .setState(new Accepted());

        FrameSender dispositionFrameSender = new FrameSender(this, FrameType.AMQP, 0, dispositionFrame, null)
                            .setValueProvider(new ValueProvider()
                            {
                                @Override
                                public void setValues()
                                {
                                    dispositionFrame.setFirst(transferMatcher.getReceivedDeliveryId());
                                }
                            });
        transferMatcher.onSuccess(dispositionFrameSender);

        addHandler(transferMatcher);
    }

    public void expectDispositionThatIsAcceptedAndSettled()
    {
        addHandler(new DispositionMatcher()
            .withSettled(equalTo(true))
            .withState(new DescriptorMatcher(Accepted.DESCRIPTOR_CODE, Accepted.DESCRIPTOR_SYMBOL)));
    }
}
