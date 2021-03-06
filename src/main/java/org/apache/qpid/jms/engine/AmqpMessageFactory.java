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
package org.apache.qpid.jms.engine;

import java.util.List;
import java.util.Map;

import org.apache.qpid.proton.amqp.Binary;
import org.apache.qpid.proton.amqp.messaging.AmqpValue;
import org.apache.qpid.proton.amqp.messaging.Data;
import org.apache.qpid.proton.amqp.messaging.Section;
import org.apache.qpid.proton.engine.Delivery;
import org.apache.qpid.proton.message.Message;

public class AmqpMessageFactory
{
    AmqpMessage createAmqpMessage(Delivery delivery, Message message, AmqpConnection amqpConnection)
    {
        Section body = message.getBody();

        if(body == null)
        {
            if(isContentType(AmqpTextMessage.CONTENT_TYPE, message))
            {
                return new AmqpTextMessage(delivery, message, amqpConnection);
            }
            else if(isContentType(AmqpObjectMessage.CONTENT_TYPE, message))
            {
                return new AmqpObjectMessage(delivery, message, amqpConnection);
            }
            else if(isContentType(AmqpBytesMessage.CONTENT_TYPE, message) || isContentType(null, message))
            {
                return new AmqpBytesMessage(delivery, message, amqpConnection);
            }
        }
        else if(body instanceof Data)
        {
            if(isContentType(AmqpTextMessage.CONTENT_TYPE, message))
            {
                return new AmqpTextMessage(delivery, message, amqpConnection);
            }
            else if(isContentType(AmqpBytesMessage.CONTENT_TYPE, message)  || isContentType(null, message))
            {
                return new AmqpBytesMessage(delivery, message, amqpConnection);
            }
            else if(isContentType(AmqpObjectMessage.CONTENT_TYPE, message))
            {
                return new AmqpObjectMessage(delivery, message, amqpConnection);
            }
        }
        else if(body instanceof AmqpValue)
        {
            Object value = ((AmqpValue) body).getValue();

            if(value == null || value instanceof String)
            {
                return new AmqpTextMessage(delivery, message, amqpConnection);
            }
            else if(value instanceof Map)
            {
                return new AmqpMapMessage(delivery, message, amqpConnection);
            }
            else if(value instanceof List)
            {
                return new AmqpListMessage(delivery, message, amqpConnection);
            }
            else if(value instanceof Binary)
            {
                return new AmqpBytesMessage(delivery, message, amqpConnection);
            }
        }

        //Unable to determine a specific message type, return the generic message
        return new AmqpGenericMessage(delivery, message, amqpConnection);
    }

    private boolean isContentType(String contentType, Message message)
    {
        if(contentType == null)
        {
            return message.getContentType() == null;
        }
        else
        {
            return contentType.equals(message.getContentType());
        }
    }

}
