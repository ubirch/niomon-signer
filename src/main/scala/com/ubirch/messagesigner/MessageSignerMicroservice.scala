package com.ubirch.messagesigner

import com.ubirch.crypto.utils.Curve
import com.ubirch.kafka.{MessageEnvelope, _}
import com.ubirch.messagesigner.StringOrByteArray._
import com.ubirch.niomon.base.{NioMicroservice, NioMicroserviceLogic}

import akka.ConfigurationException
import com.typesafe.config.Config
import net.logstash.logback.argument.StructuredArguments.v
import org.apache.kafka.clients.consumer.ConsumerRecord
import org.apache.kafka.clients.producer.ProducerRecord

class MessageSignerMicroservice(
                                 signerFactory: Config => Map[Curve, Signer],
                                 runtime: NioMicroservice[MessageEnvelope, StringOrByteArray]
                               ) extends NioMicroserviceLogic(runtime) {

  val signers: Map[Curve, Signer] = signerFactory(config)
  private final val X_UBIRCH_GATEWAY_TYPE = "X-Ubirch-Gateway-Type"
  private final val MQTT_KEY = "mqtt"
  private val mqttTopic: String = outputTopics.getOrElse(MQTT_KEY, throw new ConfigurationException("missing output topic for mqtt service"))
  private val httpTopic: String = outputTopics.getOrElse("http", throw new ConfigurationException("missing output topic for http service"))

  override def processRecord(record: ConsumerRecord[String, MessageEnvelope]): ProducerRecord[String, StringOrByteArray] = {

    val algorithm = record.findHeader("algorithm").getOrElse("unknown")
    val maybeCurve = MessageSignerMicroservice.curveFromString(algorithm)
    val requestId = record.requestIdHeader().orNull

    logger.info(s"signing response: ${record.value().ubirchPacket} algorithm=[$algorithm] | curve=[${maybeCurve.map(_.name()).getOrElse("No curve")}]", v("requestId", requestId))

    val signer = (for {
      curve <- maybeCurve
      signer <- signers.get(curve)
    } yield {
      signer
    }).getOrElse {
      val curve = Curve.Ed25519
      logger.error(s"no signer found for algorithm [$algorithm] defaulting to [${curve.toString}]")
      signers(curve)
    }

    signer.sign(record).toProducerRecord(getOutputTopic(record))
  }

  private def getOutputTopic(r: ConsumerRecord[String, MessageEnvelope]): String = {
    if (r.findHeader(X_UBIRCH_GATEWAY_TYPE).contains(MQTT_KEY)) mqttTopic
    else httpTopic
  }
}

object MessageSignerMicroservice {

  final val ECDSA_names = List(
    "ecdsa-p256v1",
    "ECC_ECDSA",
    "ECDSA",
    "SHA256withECDSA",
    "SHA512withECDSA",
    "SHA256withPLAIN-ECDSA",
    "SHA512withPLAIN-ECDSA"
  )
  final val EDDSA_names = List(
    "ed25519-sha-512",
    "ECC_ED25519",
    "Ed25519",
    "1.3.101.112"
  )

  def curveFromString(algorithm: String): Option[Curve] = {
    algorithm.toLowerCase match {
      case a if ECDSA_names.map(_.toLowerCase).contains(a) => Option(Curve.PRIME256V1)
      case a if EDDSA_names.map(_.toLowerCase).contains(a) => Option(Curve.Ed25519)
      case _ => None
    }
  }

  def normalize(algorithm: String): Option[String] = {
    algorithm.toLowerCase match {
      case a if ECDSA_names.map(_.toLowerCase).contains(a) => Option("ecdsa-p256v1")
      case a if EDDSA_names.map(_.toLowerCase).contains(a) => Option("ECC_ED25519")
      case _ => None
    }
  }

  def apply(signerFactory: Config => Map[Curve, Signer])
           (runtime: NioMicroservice[MessageEnvelope, StringOrByteArray]): MessageSignerMicroservice =
    new MessageSignerMicroservice(signerFactory, runtime)

}

