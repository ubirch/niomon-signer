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

import com.typesafe.config.Config
import com.ubirch.crypto.utils.Curve
import com.ubirch.crypto.{GeneratorKeyFactory, PrivKey}
import com.ubirch.kafka.{EnvelopeDeserializer, EnvelopeSerializer}
import com.ubirch.messagesigner.StringOrByteArray._
import com.ubirch.niomon.base.NioMicroserviceMock
import com.ubirch.protocol.ProtocolVerifier
import com.ubirch.protocol.codec.{JSONProtocolDecoder, MsgPackProtocolDecoder}
import org.apache.kafka.clients.producer.ProducerRecord
import org.apache.kafka.common.serialization.ByteArrayDeserializer
import org.bouncycastle.asn1.ASN1Sequence
import org.json4s.jackson.JsonMethods.fromJsonNode
import org.scalatest.{FlatSpec, Matchers}

//noinspection TypeAnnotation
class MessageSignerTest extends FlatSpec with Matchers {
  implicit val byteArrayDeserializer = new ByteArrayDeserializer()
  implicit val messageEnvelopeSerializer = EnvelopeSerializer

  "messageSignerFlow" should "sign binary messages with a private key - Ed25519" in {

    val curve = MessageSignerMicroservice.curveFromString("Ed25519").getOrElse(fail("No curve found"))
    val privKey = GeneratorKeyFactory.getPrivKey(curve)
    val signer = new Signer(privKey) {}
    val microservice = messageSignerMicroservice(_ => Map(curve -> signer))
    microservice.outputTopics = Map("http" -> "outgoing", "mqtt" -> "shouldnt-be-used")
    import microservice.kafkaMocks._

    testMessages.foreach(m => publishToKafka(mkBinMessage(m)))

    val res = consumeNumberMessagesFrom[Array[Byte]]("outgoing", testMessages.length)

    val ver = getVerifier(privKey)

    val decoded = res.map(MsgPackProtocolDecoder.getDecoder.decode(_, ver))

    val originalPayloads = testMessages.map(_.getBytes(UTF_8)).map(EnvelopeDeserializer.deserialize(null, _))
      .map(_.ubirchPacket.getPayload)

    val decodedPayloads = decoded.map(_.getPayload)
    decodedPayloads.map(_.asText()) should equal(originalPayloads.map(_.asText()))
  }

  it should "sign binary messages with a private key -ECDSA - StandardEncoding" in {

    val curve = MessageSignerMicroservice.curveFromString("ECDSA").getOrElse(fail("No curve found"))
    val privKey = GeneratorKeyFactory.getPrivKey(curve)
    val signer = new Signer(privKey) {}
    val microservice = messageSignerMicroservice(_ => Map(curve -> signer))
    microservice.outputTopics = Map("http" -> "outgoing", "mqtt" -> "shouldnt-be-used")
    import microservice.kafkaMocks._

    testMessages.foreach(m => publishToKafka(mkBinMessage(m).withExtraHeaders("algorithm"-> "ECDSA")))

    val res = consumeNumberMessagesFrom[Array[Byte]]("outgoing", testMessages.length)

    val ver = getVerifierECDSA(privKey)

    val decoded = res.map(MsgPackProtocolDecoder.getDecoder.decode(_, ver))

    val originalPayloads = testMessages.map(_.getBytes(UTF_8)).map(EnvelopeDeserializer.deserialize(null, _))
      .map(_.ubirchPacket.getPayload)

    decoded.map{ pm => assert(ASN1Sequence.getInstance(pm.getSignature) != null) }

    val decodedPayloads = decoded.map(_.getPayload)
    decodedPayloads.map(_.asText()) should equal(originalPayloads.map(_.asText()))

  }

  it should "sign binary messages with a private key -ECDSA - StandardEncoding for BC understood name" in {

    val curve = MessageSignerMicroservice.curveFromString("SHA256withECDSA").getOrElse(fail("No curve found"))
    val privKey = GeneratorKeyFactory.getPrivKey(curve)
    val signer = new Signer(privKey) {}
    val microservice = messageSignerMicroservice(_ => Map(curve -> signer))
    microservice.outputTopics = Map("http" -> "outgoing", "mqtt" -> "shouldnt-be-used")
    import microservice.kafkaMocks._

    testMessages.foreach(m => publishToKafka(mkBinMessage(m).withExtraHeaders("algorithm"-> "ECDSA")))

    val res = consumeNumberMessagesFrom[Array[Byte]]("outgoing", testMessages.length)

    val ver = getVerifierECDSA(privKey)

    val decoded = res.map(MsgPackProtocolDecoder.getDecoder.decode(_, ver))

    val originalPayloads = testMessages.map(_.getBytes(UTF_8)).map(EnvelopeDeserializer.deserialize(null, _))
      .map(_.ubirchPacket.getPayload)

    decoded.map{ pm => assert(ASN1Sequence.getInstance(pm.getSignature) != null) }

    val decodedPayloads = decoded.map(_.getPayload)
    decodedPayloads.map(_.asText()) should equal(originalPayloads.map(_.asText()))

  }

  it should "sign binary messages with a private key -ECDSA - PlainEncoding" in {

    val curve = MessageSignerMicroservice.curveFromString("ECDSA").getOrElse(fail("No curve found"))
    val privKey = GeneratorKeyFactory.getPrivKey(curve)
    privKey.setSignatureAlgorithm("SHA256WITHPLAIN-ECDSA")
    val signer = new Signer(privKey) {}
    val microservice = messageSignerMicroservice(_ => Map(curve -> signer))
    microservice.outputTopics = Map("http" -> "outgoing", "mqtt" -> "shouldnt-be-used")
    import microservice.kafkaMocks._

    testMessages.foreach(m => publishToKafka(mkBinMessage(m).withExtraHeaders("algorithm"-> "ECDSA")))

    val res = consumeNumberMessagesFrom[Array[Byte]]("outgoing", testMessages.length)

    val ver = getVerifierECDSA(privKey)
    val decoded = res.map(MsgPackProtocolDecoder.getDecoder.decode(_, ver))

    decoded.map{ pm => assertThrows[IllegalArgumentException](ASN1Sequence.getInstance(pm.getSignature)) }
    decoded.map{ pm => assert(pm.getSignature.length == 64) }

    val originalPayloads = testMessages.map(_.getBytes(UTF_8)).map(EnvelopeDeserializer.deserialize(null, _)).map(_.ubirchPacket.getPayload)
    val decodedPayloads = decoded.map(_.getPayload)
    assert(decodedPayloads.size ==  originalPayloads.size)
    assert(decodedPayloads.size == 4)
    decodedPayloads.map(_.asText()) should equal(originalPayloads.map(_.asText()))

  }

  it should "sign binary messages with a private key -ECDSA - PlainEncoding for BC understood name" in {

    val curve = MessageSignerMicroservice.curveFromString("SHA256WITHPLAIN-ECDSA").getOrElse(fail("No curve found"))
    val privKey = GeneratorKeyFactory.getPrivKey(curve)
    privKey.setSignatureAlgorithm("SHA256WITHPLAIN-ECDSA")
    val signer = new Signer(privKey) {}
    val microservice = messageSignerMicroservice(_ => Map(curve -> signer))
    microservice.outputTopics = Map("http" -> "outgoing", "mqtt" -> "shouldnt-be-used")
    import microservice.kafkaMocks._

    testMessages.foreach(m => publishToKafka(mkBinMessage(m).withExtraHeaders("algorithm"-> "ECDSA")))

    val res = consumeNumberMessagesFrom[Array[Byte]]("outgoing", testMessages.length)

    val ver = getVerifierECDSA(privKey)
    val decoded = res.map(MsgPackProtocolDecoder.getDecoder.decode(_, ver))

    decoded.map{ pm => assertThrows[IllegalArgumentException](ASN1Sequence.getInstance(pm.getSignature)) }
    decoded.map{ pm => assert(pm.getSignature.length == 64) }

    val originalPayloads = testMessages.map(_.getBytes(UTF_8)).map(EnvelopeDeserializer.deserialize(null, _)).map(_.ubirchPacket.getPayload)
    val decodedPayloads = decoded.map(_.getPayload)
    assert(decodedPayloads.size ==  originalPayloads.size)
    assert(decodedPayloads.size == 4)
    decodedPayloads.map(_.asText()) should equal(originalPayloads.map(_.asText()))

  }

  it should "sign binary messages with a private key with algorithm Ed25519 header" in {

    val curve = MessageSignerMicroservice.curveFromString("Ed25519").getOrElse(fail("No curve found"))
    val privKey = GeneratorKeyFactory.getPrivKey(curve)
    val signer = new Signer(privKey) {}
    val microservice = messageSignerMicroservice(_ => Map(curve -> signer))
    microservice.outputTopics = Map("http" -> "outgoing", "mqtt" -> "shouldnt-be-used")
    import microservice.kafkaMocks._

    testMessages.foreach(m => publishToKafka(mkBinMessage(m).withHeaders("algorithm"-> "Ed25519")))

    val res = consumeNumberMessagesFrom[Array[Byte]]("outgoing", testMessages.length)

    val ver = getVerifier(privKey)

    val decoded = res.map(MsgPackProtocolDecoder.getDecoder.decode(_, ver))

    val originalPayloads = testMessages.map(_.getBytes(UTF_8)).map(EnvelopeDeserializer.deserialize(null, _))
      .map(_.ubirchPacket.getPayload)

    val decodedPayloads = decoded.map(_.getPayload)
    decodedPayloads.map(_.asText()) should equal(originalPayloads.map(_.asText()))
  }

  it should "sign json messages with a private key" in {
    val curve = MessageSignerMicroservice.curveFromString("Ed25519").getOrElse(fail("No curve found"))
    val privKey = GeneratorKeyFactory.getPrivKey(curve)
    val signer = new Signer(privKey) {}
    val microservice = messageSignerMicroservice(_ => Map(curve -> signer))
    microservice.outputTopics = Map("http" -> "outgoing", "mqtt" -> "shouldnt-be-used")
    import microservice.kafkaMocks._

    testMessages.foreach(m => publishToKafka(mkJsonMessage(m)))

    val res = consumeNumberStringMessagesFrom("outgoing", testMessages.length)

    val ver = getVerifier(privKey)

    val decoded = res.map(JSONProtocolDecoder.getDecoder.decode(_, ver))

    val originalPayloads = testMessages.map(_.getBytes(UTF_8)).map(EnvelopeDeserializer.deserialize(null, _))
      .map(_.ubirchPacket.getPayload).map(fromJsonNode)

    val decodedPayloads = decoded.map(_.getPayload).map(fromJsonNode)
    decodedPayloads should equal(originalPayloads)
  }

  it should "send to outgoing-mqtt topic" in {
    val curve = MessageSignerMicroservice.curveFromString("Ed25519").getOrElse(fail("No curve found"))
    val privKey = GeneratorKeyFactory.getPrivKey(curve)
    val signer = new Signer(privKey) {}
    val microservice = messageSignerMicroservice(_ => Map(curve -> signer))
    microservice.outputTopics = Map("mqtt" -> "outgoing-mqtt", "http" -> "outgoing-http")

    import microservice.kafkaMocks._


    testMessages.foreach { m =>
      val pr = mkJsonMessage(m)
      pr.headers().add("X-Ubirch-Gateway-Type".toLowerCase, "mqtt".getBytes())
      publishToKafka(pr)
    }

    val res = consumeNumberStringMessagesFrom("outgoing-mqtt", testMessages.length)

    val ver = getVerifier(privKey)

    val decoded = res.map(JSONProtocolDecoder.getDecoder.decode(_, ver))

    val originalPayloads = testMessages.map(_.getBytes(UTF_8)).map(EnvelopeDeserializer.deserialize(null, _))
      .map(_.ubirchPacket.getPayload).map(fromJsonNode)

    val decodedPayloads = decoded.map(_.getPayload).map(fromJsonNode)
    decodedPayloads should equal(originalPayloads)
  }


  private def messageSignerMicroservice(signerFactory: Config => Map[Curve, Signer]) =
    NioMicroserviceMock(MessageSignerMicroservice(signerFactory))

  // scalastyle:off line.size.limit
  private def testMessages = List(
    """{"ubirchPacket": {"version":35,"uuid":"7fb478b7-4aba-461f-bc50-faba6d754490","chain":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==","hint":0,"payload":"some"}, "context": {}}"""
  , """{"ubirchPacket": {"version":35,"uuid":"d21c174f-5419-49d4-a614-e95ca0ea862e","chain":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==","hint":0,"payload":"some other stuff"}, "context": {}}"""
  , """{"ubirchPacket": {"version":35,"uuid":"670f05ec-c850-43a0-b6ba-225cac26e3b2","chain":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==","hint":50,"payload":[123,42,1337]}, "context": {}}"""
  , """{"ubirchPacket": {"version":35,"uuid":"8fb478b7-4aba-461f-bc50-faba6d754491","chain":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==","hint":0,"payload":"hola"}, "context": {}}""",
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


  private def getVerifierECDSA(privKey: PrivKey): ProtocolVerifier = (_: UUID, data: Array[Byte], offset: Int, len: Int, signature: Array[Byte]) => {
    val dataToVerify = data.slice(offset, offset + len)
    privKey.verify(dataToVerify, signature)
  }

}
