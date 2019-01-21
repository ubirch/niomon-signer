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

import akka.NotUsed
import akka.kafka._
import akka.kafka.scaladsl.{Consumer, Producer}
import akka.stream.scaladsl.{RestartSink, RestartSource, Sink, Source}
import org.apache.kafka.clients.consumer.ConsumerConfig
import org.apache.kafka.common.serialization.{ByteArraySerializer, Serializer, StringDeserializer, StringSerializer}

import scala.concurrent.duration._

object Kafka {
  private val consumerConfig = system.settings.config.getConfig("akka.kafka.consumer")
  private val consumerSettings: ConsumerSettings[String, String] =
    ConsumerSettings(consumerConfig, new StringDeserializer, new StringDeserializer)
      .withBootstrapServers(Config.kafkaUrl)
      .withGroupId("message-signer")
      .withProperty(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest")

  val source: Source[ConsumerMessage.CommittableMessage[String, String], NotUsed] =
    RestartSource.withBackoff(
      minBackoff = 2.seconds,
      maxBackoff = 1.minute,
      randomFactor = 0.2
    ) { () => Consumer.committableSource(consumerSettings, Subscriptions.topics(Config.incomingTopics: _*)) }

  private val producerConfig = system.settings.config.getConfig("akka.kafka.producer")
  private val producerSettings: ProducerSettings[String, StringOrByteArray] =
    ProducerSettings(producerConfig, new StringSerializer, new StringOrByteArraySerializer)
      .withBootstrapServers(Config.kafkaUrl)

  val sink: Sink[ProducerMessage.Envelope[String, StringOrByteArray, ConsumerMessage.Committable], NotUsed] =
    RestartSink.withBackoff(
      minBackoff = 2.seconds,
      maxBackoff = 1.minute,
      randomFactor = 0.2
    ) { () => Producer.commitableSink(producerSettings) }


  // TODO: use union type when/if dotty/scala3 ships
  class StringOrByteArray private(val inner: Any) // extends AnyVal // uncommenting this causes compilation error

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

  object StringOrByteArray {
    def apply(inner: String): StringOrByteArray = new StringOrByteArray(inner)

    def apply(inner: Array[Byte]): StringOrByteArray = new StringOrByteArray(inner)
  }

}
