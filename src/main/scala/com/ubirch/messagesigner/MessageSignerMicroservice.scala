package com.ubirch.messagesigner

import akka.ConfigurationException
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
  private final val GATEWAY_TYPE_HEADER = "X-Ubirch-Gateway-Key".toLowerCase
  private final val MQTT_KEY = "mqtt"
  private val mqttTopic: String = outputTopics.getOrElse(MQTT_KEY, throw new ConfigurationException("missing output topic for mqtt service"))
  private val httpTopic: String = outputTopics.getOrElse("http", throw new ConfigurationException("missing output topic for http service"))

  override def processRecord(record: ConsumerRecord[String, MessageEnvelope]): ProducerRecord[String, StringOrByteArray] = {

    val algorithm = record.findHeader("algorithm").getOrElse("unknown")
    val maybeCurve = MessageSignerMicroservice.curveFromString(algorithm)
    val requestId = record.requestIdHeader().orNull

    logger.info(s"signing response: ${record.value().ubirchPacket} algorithm=[$algorithm] | curve=[${maybeCurve.map(_.name()).getOrElse("No curve")}]", v("requestId", requestId))

    val maybeSigner = for {
      curve <- maybeCurve
      signer <- signers.get(curve)
    } yield {
      signer
    }

    val signer = maybeSigner.getOrElse {
      val curve = Curve.Ed25519
      logger.error(s"no signer found for algorithm [$algorithm] defaulting to [${curve.toString}]")
      signers(curve)
    }

    signer.sign(record).toProducerRecord(getOutputTopic(record))
  }

  private def getOutputTopic(r: ConsumerRecord[String, MessageEnvelope]): String = {
    if (r.findHeader(GATEWAY_TYPE_HEADER).contains(MQTT_KEY)) mqttTopic
    else httpTopic
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
