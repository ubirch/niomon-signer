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

package com.ubirch

import java.security.Security

import akka.NotUsed
import akka.actor.ActorSystem
import akka.kafka.ConsumerMessage.{CommittableMessage, CommittableOffset}
import akka.kafka.ProducerMessage.Message
import akka.stream.{ActorAttributes, ActorMaterializer, Supervision}
import akka.stream.scaladsl.{Flow, RunnableGraph}
import com.typesafe.scalalogging.StrictLogging
import com.ubirch.kafka.MessageEnvelope
import com.ubirch.kafka._
import com.ubirch.messagesigner.Kafka.StringOrByteArray
import com.ubirch.protocol.ProtocolException
import net.i2p.crypto.eddsa.{KeyPairGenerator => _, _}

import scala.concurrent.ExecutionContextExecutor

package object messagesigner extends StrictLogging {
  Security.addProvider(new EdDSASecurityProvider())
  Security.addProvider(new EdDSACertificateProvider())

  implicit val system: ActorSystem = ActorSystem("message-signer")
  implicit val materializer: ActorMaterializer = ActorMaterializer()
  implicit val executionContext: ExecutionContextExecutor = system.dispatcher
  val messageSignerGraph: RunnableGraph[NotUsed] = Kafka.source via messageSignerFlow(Signer) to Kafka.sink

  def messageSignerFlow(signer: Signer): Flow[CommittableMessage[String, MessageEnvelope], Message[String, StringOrByteArray, CommittableOffset], NotUsed] =
    Flow[CommittableMessage[String, MessageEnvelope]].map { msg =>
      val record = msg.record

      logger.debug(s"signing message: ${record.value().ubirchPacket}")

      val signedRecord = signer.sign(record)

      logger.debug(s"message successfully signed!")

      val recordToSend = signedRecord.toProducerRecord(Config.outgoingTopic)
      // ToDo BjB 24.09.18 : send to specific partition for completing http request
      Message[String, StringOrByteArray, CommittableOffset](
        recordToSend,
        msg.committableOffset
      )
    }.mapError { case x: Exception =>
      logger.error("unexpected error", x)
      x
    }.withAttributes(ActorAttributes.supervisionStrategy {
      // this happens when unexpected legacy packet arrives to be signed
      // it shouldn't normally happen, because message-decoder upgrades old packets
      // in the case it does happen, we drop the erroneous packet (it should be possible to recover it from the logs
      case _: ProtocolException => Supervision.Resume
      case _ => Supervision.Stop
    })

}
