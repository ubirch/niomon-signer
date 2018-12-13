package com.ubirch

import akka.{Done, NotUsed}
import akka.actor.ActorSystem
import akka.kafka._
import akka.kafka.scaladsl.Consumer.DrainingControl
import akka.kafka.scaladsl.{Consumer, Producer}
import akka.stream.ActorMaterializer
import akka.stream.scaladsl.{Keep, RestartSink, RestartSource, RunnableGraph, Sink, Source}
import com.typesafe.config.{Config, ConfigFactory}
import com.ubirch.kafkasupport.MessageEnvelope
import org.apache.kafka.clients.consumer.ConsumerConfig
import org.apache.kafka.common.serialization.{ByteArrayDeserializer, StringDeserializer, StringSerializer}

import scala.concurrent.ExecutionContextExecutor
import scala.concurrent.duration._

package object messagesigner {

  val conf: Config = ConfigFactory.load
  implicit val system: ActorSystem = ActorSystem("message-signer")
  implicit val materializer: ActorMaterializer = ActorMaterializer()
  implicit val executionContext: ExecutionContextExecutor = system.dispatcher

  private val kafkaUrl: String = conf.getString("kafka.url")


  val producerConfig: Config = system.settings.config.getConfig("akka.kafka.producer")
  val producerSettings: ProducerSettings[String, String] =
    ProducerSettings(producerConfig, new StringSerializer, new StringSerializer)
      .withBootstrapServers(kafkaUrl)


  val consumerConfig: Config = system.settings.config.getConfig("akka.kafka.consumer")
  val consumerSettings: ConsumerSettings[String, String] =
    ConsumerSettings(consumerConfig, new StringDeserializer, new StringDeserializer)
      .withBootstrapServers(kafkaUrl)
      .withGroupId("message-signer")
      .withProperty(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest")


  val incomingTopic: String = conf.getString("kafka.topic.incoming")
  val outgoingTopic: String = conf.getString("kafka.topic.outgoing")

  val kafkaSource: Source[ConsumerMessage.CommittableMessage[String, String], NotUsed] =
    RestartSource.withBackoff(
      minBackoff = 2.seconds,
      maxBackoff = 1.minute,
      randomFactor = 0.2
    ) { () => Consumer.committableSource(consumerSettings, Subscriptions.topics(incomingTopic)) }

  val kafkaSink: Sink[ProducerMessage.Envelope[String, String, ConsumerMessage.Committable], NotUsed] =
    RestartSink.withBackoff(
      minBackoff = 2.seconds,
      maxBackoff = 1.minute,
      randomFactor = 0.2
    ) { () => Producer.commitableSink(producerSettings) }


  val messageSignerStream: RunnableGraph[NotUsed] =
    kafkaSource
      .map { msg =>
        val messageEnvelope = MessageEnvelope.fromRecord(msg.record)
        val signedMessage = signPayload(messageEnvelope)

        val recordToSend = MessageEnvelope.toRecord(outgoingTopic, msg.record.key(), signedMessage)
        // ToDo BjB 24.09.18 : send to specific partition for completing http request
        ProducerMessage.Message[String, String, ConsumerMessage.CommittableOffset](
          recordToSend,
          msg.committableOffset
        )
      }
      .to(kafkaSink)

  /**
    * ToDo BjB 24.09.18 : : signing of payload should happen somewhere below
    */
  def signPayload(envelope: MessageEnvelope[String]): MessageEnvelope[String] = {
    envelope
  }
}
