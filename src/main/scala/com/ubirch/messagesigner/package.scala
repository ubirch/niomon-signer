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
import akka.stream.ActorMaterializer
import akka.stream.scaladsl.{Flow, RunnableGraph}
import com.typesafe.scalalogging.StrictLogging
import com.ubirch.kafkasupport.MessageEnvelope
import com.ubirch.messagesigner.Kafka.StringOrByteArray
import net.i2p.crypto.eddsa.{KeyPairGenerator => _, _}

import scala.concurrent.ExecutionContextExecutor

package object messagesigner extends StrictLogging {
  Security.addProvider(new EdDSASecurityProvider())
  Security.addProvider(new EdDSACertificateProvider())

  implicit val system: ActorSystem = ActorSystem("message-signer")
  implicit val materializer: ActorMaterializer = ActorMaterializer()
  implicit val executionContext: ExecutionContextExecutor = system.dispatcher
  val messageSignerGraph: RunnableGraph[NotUsed] = Kafka.source via messageSignerFlow(Signer) to Kafka.sink

  def messageSignerFlow(signer: Signer): Flow[CommittableMessage[String, String], Message[String, StringOrByteArray, CommittableOffset], NotUsed] =
    Flow[CommittableMessage[String, String]].map { msg =>
      val messageEnvelope = MessageEnvelope.fromRecord(msg.record)

      logger.debug(s"signing message: ${messageEnvelope.payload}")

      val signedMessage = signer.sign(messageEnvelope)

      val recordToSend = MessageEnvelope.toRecord(Config.outgoingTopic, msg.record.key(), signedMessage)
      // ToDo BjB 24.09.18 : send to specific partition for completing http request
      Message[String, StringOrByteArray, CommittableOffset](
        recordToSend,
        msg.committableOffset
      )
    }

}
