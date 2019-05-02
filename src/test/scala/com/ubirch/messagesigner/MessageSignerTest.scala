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

import java.io.{File, FileOutputStream}
import java.math.BigInteger
import java.nio.charset.StandardCharsets.UTF_8
import java.security.KeyStore.PrivateKeyEntry
import java.security._
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.{Date, UUID}

import com.typesafe.config.{ConfigFactory, ConfigValueFactory}
import com.ubirch.crypto.utils.Curve
import com.ubirch.crypto.{GeneratorKeyFactory, PrivKey}
import com.ubirch.kafka.{EnvelopeDeserializer, EnvelopeSerializer}
import com.ubirch.messagesigner.Keys.PublicKeyBasedCertificate
import com.ubirch.protocol.ProtocolVerifier
import com.ubirch.protocol.codec.{JSONProtocolDecoder, MsgPackProtocolDecoder}
import net.manub.embeddedkafka.EmbeddedKafka
import org.apache.kafka.clients.producer.ProducerRecord
import org.apache.kafka.common.serialization.ByteArrayDeserializer
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers
import org.bouncycastle.cert.X509v1CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.util.{PrivateKeyFactory, SubjectPublicKeyInfoFactory}
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPublicKey
import org.bouncycastle.operator.{DefaultDigestAlgorithmIdentifierFinder, DefaultSignatureAlgorithmIdentifierFinder}
import org.bouncycastle.operator.bc.BcECContentSignerBuilder
import org.json4s.jackson.JsonMethods.fromJsonNode
import org.scalatest.{BeforeAndAfterAll, FlatSpec, Matchers}

//noinspection TypeAnnotation
class MessageSignerTest extends FlatSpec with Matchers with BeforeAndAfterAll with EmbeddedKafka {
  implicit val byteArrayDeserializer = new ByteArrayDeserializer()
  implicit val messageEnvelopeSerializer = EnvelopeSerializer

  "messageSignerFlow" should "sign binary messages with a private key" in {
    withRunningKafka {
      val privKey = GeneratorKeyFactory.getPrivKey(Curve.Ed25519)
      val signer = new Signer(privKey) {}
      val microservice = new MessageSignerMicroservice(_ => signer)
      val control = microservice.run

      testMessages.foreach(m => publishToKafka(mkBinMessage(m)))

      val res = consumeNumberMessagesFrom[Array[Byte]]("outgoing", testMessages.length)

      val ver = getVerifier(privKey)

      val decoded = res.map(MsgPackProtocolDecoder.getDecoder.decode(_, ver))

      val originalPayloads = testMessages.map(_.getBytes(UTF_8)).map(EnvelopeDeserializer.deserialize(null, _))
        .map(_.ubirchPacket.getPayload)

      val decodedPayloads = decoded.map(_.getPayload)
      decodedPayloads should equal(originalPayloads)

      control.drainAndShutdown()(microservice.system.dispatcher)
    }
  }

  it should "sign json messages with a private key" in {
    withRunningKafka {
      val privKey = GeneratorKeyFactory.getPrivKey(Curve.Ed25519)
      val signer = new Signer(privKey) {}
      val microservice = new MessageSignerMicroservice(_ => signer)
      val control = microservice.run

      testMessages.foreach(m => publishToKafka(mkJsonMessage(m)))

      val res = consumeNumberStringMessagesFrom("outgoing", testMessages.length)

      val ver = getVerifier(privKey)

      val decoded = res.map(JSONProtocolDecoder.getDecoder.decode(_, ver))

      val originalPayloads = testMessages.map(_.getBytes(UTF_8)).map(EnvelopeDeserializer.deserialize(null, _))
        .map(_.ubirchPacket.getPayload).map(fromJsonNode)

      val decodedPayloads = decoded.map(_.getPayload).map(fromJsonNode)
      decodedPayloads should equal(originalPayloads)

      control.drainAndShutdown()(microservice.system.dispatcher)
    }
  }

  "PubKeyBasedCertificate" should "be able to be stored and retrieved from a keystore" in {
    val tmpFile = File.createTempFile("test", ".jks")
    tmpFile.delete()

    val c = ConfigFactory.empty()
      .withValue("certificate.password", ConfigValueFactory.fromAnyRef("myStrongPass"))
      .withValue("certificate.entryAlias", ConfigValueFactory.fromAnyRef("alias"))
      .withValue("certificate.path", ConfigValueFactory.fromAnyRef(tmpFile.getPath))

    new Keys(c).privateKey
    0
  }

  // scalastyle:off line.size.limit
  private val testMessages = List(
    """{"ubirchPacket": {"version":35,"uuid":"7fb478b7-4aba-461f-bc50-faba6d754490","chain":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==","hint":0,"payload":"some bytes!"}, "context": {}}""",
    """{"ubirchPacket": {"version":35,"uuid":"d21c174f-5419-49d4-a614-e95ca0ea862e","chain":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==","hint":0,"payload":"some other stuff"}, "context": {}}""",
    """{"ubirchPacket": {"version":35,"uuid":"670f05ec-c850-43a0-b6ba-225cac26e3b2","chain":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==","hint":50,"payload":[123,42,1337]}, "context": {}}"""
  )
  // scalastyle:on line.size.limit

  private def mkBinMessage(payload: String) = new ProducerRecord(
    "incoming", "key",
    EnvelopeDeserializer.deserialize(null, payload.getBytes(UTF_8))
  )

  private def mkJsonMessage(payload: String) = {
    val record = new ProducerRecord("incoming", "key",
      EnvelopeDeserializer.deserialize(null, payload.getBytes(UTF_8)))
    record.headers().add("Content-Type", "application/json".getBytes(UTF_8))

    record
  }

  private def getVerifier(privKey: PrivKey): ProtocolVerifier = (_: UUID, data: Array[Byte], offset: Int, len: Int, signature: Array[Byte]) => {
    val sha512 = MessageDigest.getInstance("SHA-512")
    sha512.update(data, offset, len)
    privKey.verify(sha512.digest(), signature)
  }
}
