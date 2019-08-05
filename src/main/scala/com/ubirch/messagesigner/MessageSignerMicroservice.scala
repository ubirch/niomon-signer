package com.ubirch.messagesigner

import com.typesafe.config.Config
import com.ubirch.kafka.{MessageEnvelope, _}
import com.ubirch.messagesigner.StringOrByteArray._
import com.ubirch.niomon.base.{NioMicroservice, NioMicroserviceLogic}
import net.logstash.logback.argument.StructuredArguments.v
import org.apache.kafka.clients.consumer.ConsumerRecord
import org.apache.kafka.clients.producer.ProducerRecord

class MessageSignerMicroservice(
  signerFactory: Config => Signer,
  runtime: NioMicroservice[MessageEnvelope, StringOrByteArray]
) extends NioMicroserviceLogic(runtime) {
  val signer: Signer = signerFactory(config)

  override def processRecord(record: ConsumerRecord[String, MessageEnvelope]): ProducerRecord[String, StringOrByteArray] = {
    logger.info(s"signing response: ${record.value().ubirchPacket}", v("requestId", record.key()))
    val signedRecord = signer.sign(record)
    signedRecord.toProducerRecord(onlyOutputTopic)
  }
}

object MessageSignerMicroservice {
  def apply(signerFactory: Config => Signer)
    (runtime: NioMicroservice[MessageEnvelope, StringOrByteArray]): MessageSignerMicroservice =
    new MessageSignerMicroservice(signerFactory, runtime)
}
