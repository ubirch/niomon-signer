package com.ubirch.messagesigner

import com.typesafe.config.Config
import com.ubirch.crypto.utils.Curve
import com.ubirch.kafka.{MessageEnvelope, _}
import com.ubirch.messagesigner.StringOrByteArray._
import com.ubirch.niomon.base.{NioMicroservice, NioMicroserviceLogic}
import net.logstash.logback.argument.StructuredArguments.v
import org.apache.kafka.clients.consumer.ConsumerRecord
import org.apache.kafka.clients.producer.ProducerRecord

class MessageSignerMicroservice(
                                 signerFactory: Config => Map[Curve, Signer],
                                 runtime: NioMicroservice[MessageEnvelope, StringOrByteArray]
                               ) extends NioMicroserviceLogic(runtime) {

  val signers: Map[Curve, Signer] = signerFactory(config)

  override def processRecord(record: ConsumerRecord[String, MessageEnvelope]): ProducerRecord[String, StringOrByteArray] = {
    logger.info(s"signing response: ${record.value().ubirchPacket}", v("requestId", record.key()))

    val algorithm = record.headersScala.getOrElse("algorithm", "unknown")

    val maybeSigner = for {
      curve <- MessageSignerMicroservice.curveFromString(algorithm)
      signer <- signers.get(curve)
    } yield {
      logger.debug(s"signer found for algorithm [$algorithm] -> [${curve.toString}]")
      signer
    }

    val signer = maybeSigner.getOrElse {
      val curve = Curve.Ed25519
      logger.error(s"no signer found for algorithm [$algorithm] defaulting to [${curve.toString}]")
      signers(curve)
    }

    signer.sign(record).toProducerRecord(onlyOutputTopic)

  }
}

object MessageSignerMicroservice {

  def curveFromString(algorithm: String): Option[Curve] = algorithm match {
    case "ECC_ED25519" | "Ed25519" => Some(Curve.Ed25519)
    case "ECC_ECDSA" | "ecdsa-p256v1" | "ECDSA" | "SHA256withECDSA" => Some(Curve.PRIME256V1)
    case _ => None
  }


  def apply(signerFactory: Config => Map[Curve, Signer])
           (runtime: NioMicroservice[MessageEnvelope, StringOrByteArray]): MessageSignerMicroservice =
    new MessageSignerMicroservice(signerFactory, runtime)
}
