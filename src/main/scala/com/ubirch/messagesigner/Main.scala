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

import com.ubirch.crypto.GeneratorKeyFactory
import com.ubirch.messagesigner.StringOrByteArray._
import com.ubirch.niomon.base.NioMicroserviceLive

import com.typesafe.scalalogging.StrictLogging
import org.bouncycastle.util.encoders.Base64

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

            val privKey = GeneratorKeyFactory.getPrivKey(rawKey, curve)
            val pubKey = Base64.toBase64String(privKey.getRawPublicKey)
            if(rawAlg == "ECDSA") {
              // We let our key ouput plain format for its signature (r,s)
              // BC will then internally select the proper signature algorithm
              //https://crypto.stackexchange.com/questions/57731/ecdsa-signature-rs-to-asn1-der-encoding-question
              privKey.setSignatureAlgorithm("SHA256WITHPLAIN-ECDSA")
            }
            val signer = new Signer(privKey)

            logger.debug(s"signer_detected: [rawAlg=$rawAlg] [curve=$curve.] [pubKey=$pubKey] [rawKey=***]")

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
