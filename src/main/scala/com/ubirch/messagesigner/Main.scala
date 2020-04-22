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

import com.typesafe.scalalogging.StrictLogging
import com.ubirch.crypto.GeneratorKeyFactory
import com.ubirch.messagesigner.StringOrByteArray._
import com.ubirch.niomon.base.NioMicroserviceLive

import scala.concurrent.Await
import scala.concurrent.duration.Duration

object Main extends StrictLogging {
  def main(args: Array[String]): Unit = {
    try {
      Await.result(
        NioMicroserviceLive("niomon-signer", MessageSignerMicroservice(c => {
          import collection.JavaConverters._

          c.getConfigList("private-key").asScala.map { key =>

            val rawAlg = key.getString("algorithm")
            val rawKey = key.getString("bytes").substring(0, 64)

            val curve = MessageSignerMicroservice.curveFromString(rawAlg).getOrElse {
              throw new IllegalArgumentException(s"unknown private key algorithm: $rawAlg")
            }
            val signer = new Signer(GeneratorKeyFactory.getPrivKey(rawKey, curve))

            logger.debug(s"[rawAlg=$rawAlg] [curve=$curve.] [rawKey=***]")

            curve -> signer
          }.toMap

        })).runUntilDoneAndShutdownProcess,
        Duration.Inf
      )
    } catch {
      case e: Exception =>
        logger.error("Main threw", e)
        System.exit(1)
    }
  }
}
