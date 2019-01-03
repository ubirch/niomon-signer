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

  val messageSignerGraph: RunnableGraph[NotUsed] = Kafka.source via messageSignerFlow(Signer) to Kafka.sink

}
