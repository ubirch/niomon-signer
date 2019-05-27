package com.ubirch.messagesigner

import com.typesafe.config.Config
import com.ubirch.kafka.MessageEnvelope
import com.ubirch.niomon.base.{NioMicroservice, NioMicroserviceLogic}
import com.ubirch.kafka._
import com.ubirch.messagesigner.StringOrByteArray._
import org.apache.kafka.clients.consumer.ConsumerRecord
import org.apache.kafka.clients.producer.ProducerRecord

class MessageSignerMicroservice(
  signerFactory: Config => Signer,
  runtime: NioMicroservice[MessageEnvelope, StringOrByteArray]
) extends NioMicroserviceLogic(runtime) {
  val signer: Signer = signerFactory(config)

  override def processRecord(record: ConsumerRecord[String, MessageEnvelope]): ProducerRecord[String, StringOrByteArray] = {
    logger.debug(s"signing message: ${record.value().ubirchPacket}")
    val signedRecord = signer.sign(record)
    logger.debug(s"message successfully signed!")
    signedRecord.toProducerRecord(onlyOutputTopic)
  }
}

object MessageSignerMicroservice {
  def apply(signerFactory: Config => Signer)
    (runtime: NioMicroservice[MessageEnvelope, StringOrByteArray]): MessageSignerMicroservice =
    new MessageSignerMicroservice(signerFactory, runtime)
}
