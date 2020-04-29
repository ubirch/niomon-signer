/*
 * Copyright (c) 2019 ubirch GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.ubirch.messagesigner

import com.typesafe.scalalogging.StrictLogging
import com.ubirch.client.protocol.DefaultProtocolSigner
import com.ubirch.crypto.PrivKey
import com.ubirch.kafka.{MessageEnvelope, _}
import com.ubirch.messagesigner.StringOrByteArray.StringOrByteArray
import com.ubirch.protocol.codec.{JSONProtocolEncoder, MsgPackProtocolEncoder}
import com.ubirch.protocol.{ProtocolMessage, ProtocolSigner}
import net.logstash.logback.argument.StructuredArguments.v
import org.apache.kafka.clients.consumer.ConsumerRecord

class Signer(_privateKey: => PrivKey) extends StrictLogging {
  lazy private val privateKey = _privateKey

  private val signer: ProtocolSigner = new DefaultProtocolSigner(_ => Some(privateKey))

  def sign(record: ConsumerRecord[String, MessageEnvelope]): ConsumerRecord[String, StringOrByteArray] = {
    val payload = record.value().ubirchPacket
    val (encoded, newContentType) = record.findHeader("Content-Type") match {
      case Some(ct@"application/json") => (StringOrByteArray(signAndEncodeJson(payload, record.key())), ct)
      case _ => (StringOrByteArray(signAndEncodeMsgPack(payload, record.key())), "application/octet-stream")
    }

    record.copy(value = encoded).withExtraHeaders("Content-Type" -> newContentType)
  }

  private def signAndEncodeJson(payload: ProtocolMessage, id: String): String = {
    logger.debug("encoding with JSONProtocolEncoder", v("requestId", id))
    JSONProtocolEncoder.getEncoder.encode(payload, signer)
  }

  private def signAndEncodeMsgPack(payload: ProtocolMessage, id: String): Array[Byte] = {
    logger.debug("encoding with MsgPackProtocolEncoder", v("requestId", id))
    MsgPackProtocolEncoder.getEncoder.encode(payload, signer)
  }
}
