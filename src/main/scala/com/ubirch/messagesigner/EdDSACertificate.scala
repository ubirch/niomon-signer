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

//noinspection NotImplementedCode
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

//noinspection NotImplementedCode
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
