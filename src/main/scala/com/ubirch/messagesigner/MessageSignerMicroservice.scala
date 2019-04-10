package com.ubirch.messagesigner

import java.util

import com.typesafe.config.Config
import com.ubirch.kafka.MessageEnvelope
import com.ubirch.niomon.base.NioMicroservice
import com.ubirch.kafka._
import com.ubirch.messagesigner.MessageSignerMicroservice.MessageEnvelopeOrString
import com.ubirch.messagesigner.MessageSignerMicroservice.MessageEnvelopeOrString._
import com.ubirch.messagesigner.StringOrByteArray._
import com.ubirch.niomon.util.KafkaPayload
import org.apache.kafka.clients.consumer.ConsumerRecord
import org.apache.kafka.clients.producer.ProducerRecord
import org.apache.kafka.common.serialization.{Deserializer, Serializer, StringDeserializer, StringSerializer}

import scala.util.Try

class MessageSignerMicroservice(signerFactory: Config => Signer) extends NioMicroservice[MessageEnvelopeOrString, StringOrByteArray]("message-signer") {
  val signer: Signer = signerFactory(config)

  override def processRecord(record: ConsumerRecord[String, MessageEnvelopeOrString]): ProducerRecord[String, StringOrByteArray] = {
    record.value() match {
      case Right(s) =>
        record.toProducerRecord(topic = outputTopics.values.head, value = StringOrByteArray(s))
      case Left(me) =>
        val messageEnvelopeRecord = record.copy[String, MessageEnvelope](value = me)
        logger.debug(s"signing message: ${messageEnvelopeRecord.value().ubirchPacket}")
        val signedRecord = signer.sign(messageEnvelopeRecord)
        logger.debug(s"message successfully signed!")
        signedRecord.toProducerRecord(outputTopics.values.head)
    }
  }
}

object MessageSignerMicroservice {

  type MessageEnvelopeOrString = Either[MessageEnvelope, String]

  object MessageEnvelopeOrString {
    def apply(inner: MessageEnvelope): MessageEnvelopeOrString = Left(inner)

    def apply(inner: String): MessageEnvelopeOrString = Right(inner)

    implicit val MessageEnvelopeOrStringKafkaPayload: KafkaPayload[MessageEnvelopeOrString] =
      new KafkaPayload[MessageEnvelopeOrString] {
        override def deserializer: Deserializer[MessageEnvelopeOrString] = new Deserializer[MessageEnvelopeOrString] {
          private val messageEnvelopeDeserializer = EnvelopeDeserializer
          private val stringDeserializer = new StringDeserializer()

          override def configure(configs: util.Map[String, _], isKey: Boolean): Unit = {
            messageEnvelopeDeserializer.configure(configs, isKey)
            stringDeserializer.configure(configs, isKey)
          }

          override def deserialize(topic: String, data: Array[Byte]): MessageEnvelopeOrString = {
            Try(apply(messageEnvelopeDeserializer.deserialize(topic, data)))
              .getOrElse(apply(stringDeserializer.deserialize(topic, data)))
          }

          override def close(): Unit = {
            messageEnvelopeDeserializer.close()
            stringDeserializer.close()
          }
        }

        override def serializer: Serializer[MessageEnvelopeOrString] = new Serializer[MessageEnvelopeOrString] {
          private val messageEnvelopeSerializer = EnvelopeSerializer
          private val stringSerializer = new StringSerializer()

          override def configure(configs: util.Map[String, _], isKey: Boolean): Unit = {
            messageEnvelopeSerializer.configure(configs, isKey)
            stringSerializer.configure(configs, isKey)
          }

          override def serialize(topic: String, data: MessageEnvelopeOrString): Array[Byte] = {
            data match {
              case Left(me) => messageEnvelopeSerializer.serialize(topic, me)
              case Right(s) => stringSerializer.serialize(topic, s)
            }
          }

          override def close(): Unit = {
            messageEnvelopeSerializer.close()
            stringSerializer.close()
          }
        }
      }
  }

}
