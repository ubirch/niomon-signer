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

import java.nio.charset.StandardCharsets.UTF_8
import java.security._
import java.util.UUID

import com.ubirch.kafka.{EnvelopeDeserializer, EnvelopeSerializer}
import com.ubirch.protocol.ProtocolVerifier
import com.ubirch.protocol.codec.{JSONProtocolDecoder, MsgPackProtocolDecoder}
import net.i2p.crypto.eddsa.{KeyPairGenerator => _, _}
import net.manub.embeddedkafka.EmbeddedKafka
import org.apache.kafka.clients.producer.ProducerRecord
import org.apache.kafka.common.serialization.ByteArrayDeserializer
import org.json4s.jackson.JsonMethods.fromJsonNode
import org.scalatest.{BeforeAndAfterAll, FlatSpec, Matchers}

//noinspection TypeAnnotation
class MessageSignerTest extends FlatSpec with Matchers with BeforeAndAfterAll with EmbeddedKafka {
  implicit val byteArrayDeserializer = new ByteArrayDeserializer()
  implicit val messageEnvelopeSerializer = EnvelopeSerializer

  "messageSignerFlow" should "sign binary messages with a private key" in {
    withRunningKafka {
      val kPair = KeyPairGenerator.getInstance(EdDSAKey.KEY_ALGORITHM).generateKeyPair()
      val signer = new Signer(kPair.getPrivate.asInstanceOf[EdDSAPrivateKey]) {}
      val microservice = new MessageSignerMicroservice(_ => signer)
      val control = microservice.run

      testMessages.foreach(m => publishToKafka(mkBinMessage(m)))

      val res = consumeNumberMessagesFrom[Array[Byte]]("outgoing", testMessages.length)

      val ver = getVerifier(kPair)

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
      val kPair = KeyPairGenerator.getInstance(EdDSAKey.KEY_ALGORITHM).generateKeyPair()
      val signer = new Signer(kPair.getPrivate.asInstanceOf[EdDSAPrivateKey]) {}
      val microservice = new MessageSignerMicroservice(_ => signer)
      val control = microservice.run

      testMessages.foreach(m => publishToKafka(mkJsonMessage(m)))

      val res = consumeNumberStringMessagesFrom("outgoing", testMessages.length)

      val ver = getVerifier(kPair)

      val decoded = res.map(JSONProtocolDecoder.getDecoder.decode(_, ver))

      val originalPayloads = testMessages.map(_.getBytes(UTF_8)).map(EnvelopeDeserializer.deserialize(null, _))
        .map(_.ubirchPacket.getPayload).map(fromJsonNode)

      val decodedPayloads = decoded.map(_.getPayload).map(fromJsonNode)
      decodedPayloads should equal(originalPayloads)

      control.drainAndShutdown()(microservice.system.dispatcher)
    }
  }

  // scalastyle:off line.size.limit
  private val testMessages = List(
    """{"ubirchPacket": {"version":35,"uuid":"7fb478b7-4aba-461f-bc50-faba6d754490","chain":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==","hint":0,"payload":"some bytes!"}, "context": {}}""",
    """{"ubirchPacket": {"version":35,"uuid":"d21c174f-5419-49d4-a614-e95ca0ea862e","chain":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==","hint":0,"payload":"some other stuff"}, "context": {}}""",
    """{"ubirchPacket": {"version":35,"uuid":"670f05ec-c850-43a0-b6ba-225cac26e3b2","chain":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==","hint":50,"payload":[123,42,1337]}, "context": {}}"""
  )
  // scalastyle:on line.size.limit

  override protected def beforeAll(): Unit = {
    Security.addProvider(new EdDSASecurityProvider())
    Security.addProvider(new EdDSACertificateProvider())
  }

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

  private def getVerifier(kPair: KeyPair): ProtocolVerifier = (_: UUID, data: Array[Byte], offset: Int, len: Int, signature: Array[Byte]) => {
    val sha512 = MessageDigest.getInstance("SHA-512")
    sha512.update(data, offset, len)
    val hash = sha512.digest()

    val sig = Signature.getInstance(EdDSAEngine.SIGNATURE_ALGORITHM)
    sig.initVerify(new EdDSACertificate(kPair.getPublic.asInstanceOf[EdDSAPublicKey]))
    sig.setParameter(EdDSAEngine.ONE_SHOT_MODE)
    sig.update(hash)

    sig.verify(signature)
  }
}
