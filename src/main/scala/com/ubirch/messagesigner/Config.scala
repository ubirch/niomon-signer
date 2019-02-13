/*
 * Copyright (c) 2019 ubirch GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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