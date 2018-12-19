package com.ubirch

import java.security.Security

import akka.NotUsed
import akka.actor.ActorSystem
import akka.kafka._
import akka.stream.ActorMaterializer
import akka.stream.scaladsl.RunnableGraph
import com.ubirch.kafkasupport.MessageEnvelope
import com.ubirch.messagesigner.Kafka.StringOrByteArray
import net.i2p.crypto.eddsa.{KeyPairGenerator => _, _}

import scala.concurrent.ExecutionContextExecutor

package object messagesigner {
  Security.addProvider(new EdDSASecurityProvider())
  Security.addProvider(new EdDSACertificateProvider())

  implicit val system: ActorSystem = ActorSystem("message-signer")
  implicit val materializer: ActorMaterializer = ActorMaterializer()
  implicit val executionContext: ExecutionContextExecutor = system.dispatcher

  val messageSignerStream: RunnableGraph[NotUsed] =
    Kafka.source
      .map { msg =>
        val messageEnvelope = MessageEnvelope.fromRecord(msg.record)
        val signedMessage = Signer.sign(messageEnvelope)

        val recordToSend = MessageEnvelope.toRecord(Config.outgoingTopic, msg.record.key(), signedMessage)
        // ToDo BjB 24.09.18 : send to specific partition for completing http request
        ProducerMessage.Message[String, StringOrByteArray, ConsumerMessage.CommittableOffset](
          recordToSend,
          msg.committableOffset
        )
      }
      .to(Kafka.sink)

}
