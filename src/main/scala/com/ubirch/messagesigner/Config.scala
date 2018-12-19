package com.ubirch.messagesigner

import java.nio.file.{Path, Paths}

import com.typesafe.config.ConfigFactory

import scala.collection.JavaConverters._

object Config {
  private val conf = ConfigFactory.load

  val kafkaUrl: String = conf.getString("kafka.url")
  val incomingTopics: List[String] = conf.getStringList("kafka.topic.incoming").asScala.toList
  val outgoingTopic: String = conf.getString("kafka.topic.outgoing")

  val keyStoreFilename: Path = Paths.get(conf.getString("certificate.path"))
  val keyStorePassword: String = conf.getString("certificate.password")
  val keyStoreEntryAlias: String = conf.getString("certificate.entryAlias")
}
