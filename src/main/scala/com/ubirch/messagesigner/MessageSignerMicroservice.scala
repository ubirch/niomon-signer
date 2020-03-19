package com.ubirch.messagesigner

import com.typesafe.config.Config
import com.ubirch.kafka.{MessageEnvelope, _}
import com.ubirch.messagesigner.StringOrByteArray._
import com.ubirch.niomon.base.{NioMicroservice, NioMicroserviceLogic}
import net.logstash.logback.argument.StructuredArguments.v
import org.apache.kafka.clients.consumer.ConsumerRecord
import org.apache.kafka.clients.producer.ProducerRecord

class MessageSignerMicroservice(
                                 signerFactory: Config => Map[String, Signer],
                                 runtime: NioMicroservice[MessageEnvelope, StringOrByteArray]
                               ) extends NioMicroserviceLogic(runtime) {
  val signers: Map[String, Signer] = signerFactory(config)

  override def processRecord(record: ConsumerRecord[String, MessageEnvelope]): ProducerRecord[String, StringOrByteArray] = {
    logger.info(s"signing response: ${record.value().ubirchPacket}", v("requestId", record.key()))


    val algorithm = record.headersScala.getOrElse("algorithm", "unknown")
    signers.get(algorithm) match {
      case Some(signer) => signer.sign(record).toProducerRecord(onlyOutputTopic)
      case None =>
        logger.error(s"no signer found for algorithm [${algorithm}]")
        signers("Ed25519").sign(record).toProducerRecord(onlyOutputTopic)
    }
  }
}

object MessageSignerMicroservice {
  def apply(signerFactory: Config => Map[String, Signer])
           (runtime: NioMicroservice[MessageEnvelope, StringOrByteArray]): MessageSignerMicroservice =
    new MessageSignerMicroservice(signerFactory, runtime)
}
