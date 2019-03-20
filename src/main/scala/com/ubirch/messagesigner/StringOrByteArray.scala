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

import java.util

import com.ubirch.niomon.base.KafkaPayload
import org.apache.kafka.common.serialization._

// TODO: use union type when/if dotty/scala3 ships
class StringOrByteArray private(val inner: Any) // extends AnyVal // uncommenting this causes compilation error

object StringOrByteArray {
  def apply(inner: String): StringOrByteArray = new StringOrByteArray(inner)

  def apply(inner: Array[Byte]): StringOrByteArray = new StringOrByteArray(inner)

  implicit val stringOrByteArrayKafkaPayload: KafkaPayload[StringOrByteArray] = new KafkaPayload[StringOrByteArray] {
    override def deserializer: Deserializer[StringOrByteArray] = new Deserializer[StringOrByteArray] {
      override def deserialize(topic: String, data: Array[Byte]): StringOrByteArray = StringOrByteArray(data)
      override def configure(configs: util.Map[String, _], isKey: Boolean): Unit = {}
      override def close(): Unit = {}
    }

    override def serializer: Serializer[StringOrByteArray] = new StringOrByteArraySerializer
  }

  class StringOrByteArraySerializer extends Serializer[StringOrByteArray] {
    val stringSerializer = new StringSerializer
    val byteArraySerializer = new ByteArraySerializer

    override def configure(configs: util.Map[String, _], isKey: Boolean): Unit = {
      stringSerializer.configure(configs, isKey)
      byteArraySerializer.configure(configs, isKey)
    }

    override def serialize(topic: String, data: StringOrByteArray): Array[Byte] = {
      data.inner match {
        case s: String => stringSerializer.serialize(topic, s)
        case ba: Array[Byte] => byteArraySerializer.serialize(topic, ba)
        case x: Any => throw new IllegalArgumentException(
          s"StringOrByteArraySerializer cannot serialize value of type ${x.getClass.getCanonicalName}"
        )
      }
    }

    override def close(): Unit = {
      stringSerializer.close()
      byteArraySerializer.close()
    }
  }

}
