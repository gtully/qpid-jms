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
package org.apache.qpid.jms.engine;

import java.util.UUID;

import org.apache.qpid.proton.amqp.messaging.Source;
import org.apache.qpid.proton.amqp.messaging.Target;
import org.apache.qpid.proton.amqp.transport.ErrorCondition;
import org.apache.qpid.proton.amqp.transport.ReceiverSettleMode;
import org.apache.qpid.proton.amqp.transport.SenderSettleMode;
import org.apache.qpid.proton.engine.Receiver;
import org.apache.qpid.proton.engine.Sender;
import org.apache.qpid.proton.engine.Session;

public class AmqpSession
{
    private final AmqpConnection _amqpConnection;
    private final Session _protonSession;
    private boolean _established;

    private boolean _closed;

    public AmqpSession(AmqpConnection amqpConnection, Session protonSession)
    {
        _amqpConnection = amqpConnection;
        _protonSession = protonSession;
    }

    public boolean isEstablished()
    {
        return _established;
    }

    void setEstablished()
    {
        _established = true;
    }

    public void close()
    {
        _protonSession.close();
        _amqpConnection.addPendingCloseSession(_protonSession);
    }

    void setClosed()
    {
        _closed = true;
    }

    AmqpConnection getAmqpConnection()
    {
        return _amqpConnection;
    }

    public AmqpSender createAmqpSender(String address)
    {
        String sourceAddress = UUID.randomUUID().toString();
        org.apache.qpid.proton.amqp.messaging.Source source = new Source();
        source.setAddress(sourceAddress);

        Target target = new Target();
        target.setAddress(address);

        String senderName = address + "<-" + sourceAddress;
        Sender protonSender = _protonSession.sender(senderName);

        protonSender.setSource(source);
        protonSender.setTarget(target);

        // set settle modes to give "at-least-once" semantics
        protonSender.setSenderSettleMode(SenderSettleMode.UNSETTLED);
        protonSender.setReceiverSettleMode(ReceiverSettleMode.FIRST);

        AmqpSender amqpSender = new AmqpSender(this, protonSender, _amqpConnection);
        protonSender.setContext(amqpSender);
        protonSender.open();
        _amqpConnection.addPendingLink(protonSender);

        return amqpSender;
    }

    public AmqpReceiver createAmqpReceiver(String address)
    {
        String name = address + "->" + UUID.randomUUID().toString();
        Receiver protonReceiver = _protonSession.receiver(name);

        Source source = new Source();
        source.setAddress(address);
        protonReceiver.setSource(source);

        Target target = new Target();
        protonReceiver.setTarget(target);

        protonReceiver.setSenderSettleMode(SenderSettleMode.UNSETTLED);
        protonReceiver.setReceiverSettleMode(ReceiverSettleMode.FIRST);

        AmqpReceiver amqpReceiver = new AmqpReceiver(this, protonReceiver, _amqpConnection);
        protonReceiver.setContext(amqpReceiver);
        protonReceiver.open();
        _amqpConnection.addPendingLink(protonReceiver);

        return amqpReceiver;
    }

    public boolean isClosed()
    {
        return _closed;
    }

    public ErrorCondition getSessionError()
    {
        return _protonSession.getCondition();
    }
}
