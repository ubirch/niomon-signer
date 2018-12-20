package com.ubirch.messagesigner

import java.security.{MessageDigest, Signature}
import java.util.UUID

import com.ubirch.kafkasupport.MessageEnvelope
import com.ubirch.messagesigner.Kafka.StringOrByteArray
import com.ubirch.protocol.codec.{JSONProtocolDecoder, JSONProtocolEncoder, MsgPackProtocolEncoder}
import com.ubirch.protocol.{ProtocolMessage, ProtocolSigner}
import net.i2p.crypto.eddsa.{EdDSAEngine, EdDSAPrivateKey}

object Signer extends Signer(Keys.privateKey)

abstract class Signer(_privateKey: => EdDSAPrivateKey) {
  lazy private val privateKey = _privateKey

  def sign(envelope: MessageEnvelope[String]): MessageEnvelope[StringOrByteArray] = {
    val payload = JSONProtocolDecoder.getDecoder.decode(envelope.payload)
    val (encoded, newContentType) = envelope.headers.get("Content-Type") match {
      case Some(ct@"application/json") => (StringOrByteArray(signAndEncodeJson(payload)), ct)
      case _ => (StringOrByteArray(signAndEncodeMsgPack(payload)), "application/octet-stream")
    }

    val newHeaders = envelope.headers + ("Content-Type" -> newContentType)

    MessageEnvelope(encoded, newHeaders)
  }

  private val signer: ProtocolSigner = (_: UUID, data: Array[Byte], offset: Int, len: Int) => {
    val sha512 = MessageDigest.getInstance("SHA-512")
    sha512.update(data, offset, len)
    val hash = sha512.digest()

    val sig = Signature.getInstance(EdDSAEngine.SIGNATURE_ALGORITHM)
    sig.initSign(privateKey)
    sig.setParameter(EdDSAEngine.ONE_SHOT_MODE)
    sig.update(hash)
    val signature = sig.sign()

    signature
  }

  private def signAndEncodeJson(payload: ProtocolMessage): String = {
    JSONProtocolEncoder.getEncoder.encode(payload, signer)
  }

  private def signAndEncodeMsgPack(payload: ProtocolMessage): Array[Byte] = {
    MsgPackProtocolEncoder.getEncoder.encode(payload, signer)
  }
}
