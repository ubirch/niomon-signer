package com.ubirch.messagesigner

// this file is copied from ubirch-validator project
// TODO: extract this to a separate library

import java.io.InputStream
import java.security._
import java.security.cert.{CRL, Certificate, CertificateFactorySpi}
import java.security.spec.X509EncodedKeySpec
import java.util
import java.util.Base64

import net.i2p.crypto.eddsa.{EdDSAKey, EdDSAPublicKey}
import org.apache.commons.io.IOUtils

class EdDSACertificate(pub: EdDSAPublicKey) extends Certificate(EdDSAKey.KEY_ALGORITHM) {
  override def getEncoded: Array[Byte] = pub.getEncoded
  override def getPublicKey: EdDSAPublicKey = pub
  override def toString: String = s"EdDSA Certificate [${Base64.getEncoder.encodeToString(pub.getAbyte)}]"

  override def verify(key: PublicKey): Unit = ???
  override def verify(key: PublicKey, sigProvider: String): Unit = ???
}

class EdDSACertificateProvider extends Provider("EdDSACertificateProvider", 0.1, "EdDSACertificateProvider") {
  AccessController.doPrivileged(new PrivilegedAction[Unit] {
    override def run(): Unit = {
      put("CertificateFactory." + EdDSAKey.KEY_ALGORITHM, classOf[EdDSACertificateFactory].getCanonicalName)
    }
  })
}

class EdDSACertificateFactory extends CertificateFactorySpi {
  override def engineGenerateCertificate(inStream: InputStream): EdDSACertificate = {
    val bytes = IOUtils.toByteArray(inStream)
    val key = new EdDSAPublicKey(new X509EncodedKeySpec(bytes))
    new EdDSACertificate(key)
  }

  override def engineGenerateCertificates(inStream: InputStream): util.Collection[_ <: Certificate] = ???
  override def engineGenerateCRL(inStream: InputStream): CRL = ???
  override def engineGenerateCRLs(inStream: InputStream): util.Collection[_ <: CRL] = ???
}