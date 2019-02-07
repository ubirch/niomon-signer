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
import java.util.concurrent.CompletionStage

import akka.Done
import akka.kafka.ConsumerMessage
import akka.kafka.ConsumerMessage.CommittableOffset
import akka.stream.scaladsl.{Keep, Sink, Source}
import com.ubirch.kafka.EnvelopeDeserializer
import com.ubirch.protocol.ProtocolVerifier
import com.ubirch.protocol.codec.{JSONProtocolDecoder, MsgPackProtocolDecoder}
import net.i2p.crypto.eddsa.{KeyPairGenerator => _, _}
import org.apache.kafka.clients.consumer.ConsumerRecord
import org.scalatest.{BeforeAndAfterAll, FlatSpec, Matchers}
import org.json4s.jackson.JsonMethods.fromJsonNode

import scala.concurrent.duration._
import scala.concurrent.{Await, Future}

class MessageSignerTest extends FlatSpec with Matchers with BeforeAndAfterAll {

  "messageSignerFlow" should "sign binary messages with a private key" in {
    val kPair = KeyPairGenerator.getInstance(EdDSAKey.KEY_ALGORITHM).generateKeyPair()
    val signer = new Signer(kPair.getPrivate.asInstanceOf[EdDSAPrivateKey]) {}
    val flow = messageSignerFlow(signer)

    val graph = Source[String](testMessages).map(mkBinMessage).via(flow).toMat(Sink.seq)(Keep.right)
    val res = Await.result(graph.run(), 3.seconds)

    val ver = getVerifier(kPair)

    val decoded = res.map { r =>
      val v = r.record.value()
      v.inner shouldBe an[Array[Byte]]
      MsgPackProtocolDecoder.getDecoder.decode(v.inner.asInstanceOf[Array[Byte]], ver)
    }

    val originalPayloads = testMessages.map(_.getBytes(UTF_8)).map(EnvelopeDeserializer.deserialize(null, _))
      .map(_.ubirchPacket.getPayload)

    val decodedPayloads = decoded.map(_.getPayload).toList
    decodedPayloads should equal(originalPayloads)
  }

  it should "sign json messages with a private key" in {
    val kPair = KeyPairGenerator.getInstance(EdDSAKey.KEY_ALGORITHM).generateKeyPair()
    val signer = new Signer(kPair.getPrivate.asInstanceOf[EdDSAPrivateKey]) {}
    val flow = messageSignerFlow(signer)

    val graph = Source[String](testMessages).map(mkJsonMessage).via(flow).toMat(Sink.seq)(Keep.right)
    val res = Await.result(graph.run(), 3.seconds)

    val ver = getVerifier(kPair)

    val decoded = res.map { r =>
      val v = r.record.value()
      v.inner shouldBe a[String]
      JSONProtocolDecoder.getDecoder.decode(v.inner.asInstanceOf[String], ver)
    }

    val originalPayloads = testMessages.map(_.getBytes(UTF_8)).map(EnvelopeDeserializer.deserialize(null, _))
      .map(_.ubirchPacket.getPayload).map(fromJsonNode)

    val decodedPayloads = decoded.map(_.getPayload).map(fromJsonNode).toList
    decodedPayloads should equal (originalPayloads)
  }

  // scalastyle:off line.size.limit
  private val testMessages = List(
    """{"ubirchPacket": {"version":19,"uuid":"7fb478b7-4aba-461f-bc50-faba6d754490","chain":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==","hint":0,"signed":"lhOwf7R4t0q6Rh+8UPq6bXVEkNoAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAq3NvbWUgYnl0ZXMh","signature":"2+E3O/lYub2LM5LbFE2qDMApCFLTLxKtYK6vE2bcT1k+EiUWHAXBFJztcMLryd5JK8dqQI0B2QFTETIFNQReDQ==","payload":"some bytes!"}, "context": {}}""",
    """{"ubirchPacket": {"version":19,"uuid":"d21c174f-5419-49d4-a614-e95ca0ea862e","chain":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==","hint":0,"signed":"lhOw0hwXT1QZSdSmFOlcoOqGLtoAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAsHNvbWUgb3RoZXIgc3R1ZmY=","signature":"r8+yz+omS35tBnAc6QTVAE5tbJcU4QSjf1mHgD/3f0eiWOfzGT0cKwmdJf/1W4LSr0pXZWaoPrF0oIxsW+fHDw==","payload":"some other stuff"}, "context": {}}""",
    """{"ubirchPacket": {"version":19,"uuid":"670f05ec-c850-43a0-b6ba-225cac26e3b2","chain":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==","hint":50,"signed":"lhOwZw8F7MhQQ6C2uiJcrCbjstoAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAyk3sqzQU5","signature":"wo8xg5z+j4EVKhDLYZS57HgxSoGwdxsPx6+7BG3HzNyqRy4j4vv+Jff+r3iLrQDxO6w6ffwKSS+RuwC7FxyKAQ==","payload":[123,42,1337]}, "context": {}}"""
  )
  // scalastyle:on line.size.limit

  //noinspection NotImplementedCode
  private val dummyCommitableOffset = new CommittableOffset {
    override def partitionOffset: ConsumerMessage.PartitionOffset = ???

    override def commitScaladsl(): Future[Done] = ???

    override def commitJavadsl(): CompletionStage[Done] = ???
  }

  override protected def beforeAll(): Unit = {
    Security.addProvider(new EdDSASecurityProvider())
    Security.addProvider(new EdDSACertificateProvider())
  }

  private def mkBinMessage(payload: String) = ConsumerMessage.CommittableMessage(
    record = new ConsumerRecord("topic", 0, 0, "key",
      EnvelopeDeserializer.deserialize(null, payload.getBytes(UTF_8))),
    committableOffset = dummyCommitableOffset
  )

  private def mkJsonMessage(payload: String) = {
    val record = new ConsumerRecord("topic", 0, 0, "key",
      EnvelopeDeserializer.deserialize(null, payload.getBytes(UTF_8)))
    record.headers().add("Content-Type", "application/json".getBytes(UTF_8))

    ConsumerMessage.CommittableMessage(record, dummyCommitableOffset)
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
