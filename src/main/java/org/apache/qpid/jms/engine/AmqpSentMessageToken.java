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

import org.apache.qpid.proton.amqp.transport.DeliveryState;
import org.apache.qpid.proton.engine.Delivery;

public class AmqpSentMessageToken
{
    private Delivery _delivery;
    private AmqpSender _amqpSender;
    private AmqpConnection _amqpConnection;

    public AmqpSentMessageToken(Delivery delivery, AmqpSender sender)
    {
        _delivery = delivery;
        _amqpSender = sender;
        _amqpConnection = _amqpSender.getAmqpConnection();
    }

    public DeliveryState getRemoteDeliveryState()
    {
        synchronized (_amqpConnection)
        {
            return _delivery.getRemoteState();
        }
    }

    public void settle()
    {
        synchronized (_amqpConnection)
        {
            _delivery.settle();
        }
    }

    @Override
    public String toString()
    {
        StringBuilder builder = new StringBuilder();
        builder.append("AmqpSentMessage [_delivery=").append(_delivery)
            .append("]");
        return builder.toString();
    }
}
