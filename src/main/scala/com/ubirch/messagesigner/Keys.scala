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

import java.io.{FileInputStream, FileOutputStream, InputStream}
import java.math.BigInteger
import java.nio.file.{Files, Paths}
import java.security.{AccessController, KeyStore, PrivilegedAction, Provider, PublicKey, Security}
import java.security.KeyStore.PrivateKeyEntry
import java.security.cert.{CRL, Certificate, CertificateFactorySpi}
import java.security.spec.X509EncodedKeySpec
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.{Base64, Date}
import java.util

import com.typesafe.config.Config
import com.typesafe.scalalogging.StrictLogging
import com.ubirch.crypto.utils.Curve
import com.ubirch.crypto.{GeneratorKeyFactory, PrivKey}
import com.ubirch.messagesigner.Keys.{PublicKeyBasedCertificate, PublicKeyBasedCertificateProvider}
import org.apache.commons.io.IOUtils
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers
import org.bouncycastle.cert.X509v1CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.crypto.params.{Ed25519PrivateKeyParameters, Ed25519PublicKeyParameters}
import org.bouncycastle.crypto.util.{PrivateKeyFactory, SubjectPublicKeyInfoFactory}
import org.bouncycastle.jcajce.provider.asymmetric.edec.{BCEdDSAPublicKey, KeyFactorySpi}
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.{DefaultDigestAlgorithmIdentifierFinder, DefaultSignatureAlgorithmIdentifierFinder}
import org.bouncycastle.operator.bc.{BcDSAContentSignerBuilder, BcECContentSignerBuilder}

class Keys(conf: Config) extends StrictLogging {
  private val pass = conf.getString("certificate.password").toCharArray
  private val entryAlias = conf.getString("certificate.entryAlias")
  private val privateKeyAlias = "pke_" + entryAlias

  lazy val privateKey: PrivKey = keyStore.getKey(privateKeyAlias, pass).asInstanceOf[PrivKey]

  lazy private val keyStore: KeyStore = {
    val ks = KeyStore.getInstance("jks")
    val fName = Paths.get(conf.getString("certificate.path"))

    if (Files.exists(fName)) {
      val ksFileInputStream = new FileInputStream(fName.toFile)
      ks.load(ksFileInputStream, pass)
    } else {
      logger.error(s"key store not found: $fName")
      ks.load(null, pass) // create an empty keystore
      //throw new FileNotFoundException(s"key store not found: $fName")
    }

    // generate the key pair if not present
    if (!ks.containsAlias(entryAlias)) {
      logger.warn(s"no private key found: '$entryAlias', generating new private key")

      val privKey = GeneratorKeyFactory.getPrivKey(Curve.Ed25519)

      ks.setEntry(
        privateKeyAlias,
        new PrivateKeyEntry(privKey.getPrivateKey, Array(new PublicKeyBasedCertificate(privKey.getPublicKey))),
        new KeyStore.PasswordProtection(pass)
      )

      val fos = new FileOutputStream(fName.toFile)
      ks.store(fos, pass)
      fos.close()
    }

    ks
  }
}

object Keys {
  val KEY_ALGORITHM = "THISISACTUALLYNOTACERTIFICATE"
  Security.addProvider(new PublicKeyBasedCertificateProvider())
  Security.addProvider(new BouncyCastleProvider())

  //noinspection NotImplementedCode
  class PublicKeyBasedCertificate(pub: PublicKey) extends Certificate(KEY_ALGORITHM) {
    override def getEncoded: Array[Byte] = pub.getEncoded

    override def getPublicKey: PublicKey = pub

    override def toString: String = s"Not Actually A Certificate [${Base64.getEncoder.encodeToString(getEncoded)}]"

    override def verify(key: PublicKey): Unit = ???

    override def verify(key: PublicKey, sigProvider: String): Unit = ???
  }

  class PublicKeyBasedCertificateProvider extends Provider("PublicKeyBasedCertificateProvider", 0.1, "PublicKeyBasedCertificateProvider") {
    AccessController.doPrivileged(new PrivilegedAction[Unit] {
      override def run(): Unit = {
        put("CertificateFactory." + KEY_ALGORITHM, classOf[PublicKeyBasedCertificateFactory].getCanonicalName)
      }
    })
  }

  //noinspection NotImplementedCode
  class PublicKeyBasedCertificateFactory extends CertificateFactorySpi {
    override def engineGenerateCertificate(inStream: InputStream): PublicKeyBasedCertificate = {
      val bytes = IOUtils.toByteArray(inStream)
      val key = {
        val keyFactory = new KeyFactorySpi.ED25519()
        keyFactory.generatePublic(SubjectPublicKeyInfo.getInstance(bytes))
      }
      new PublicKeyBasedCertificate(key)
    }

    override def engineGenerateCertificates(inStream: InputStream): util.Collection[_ <: Certificate] = ???

    override def engineGenerateCRL(inStream: InputStream): CRL = ???

    override def engineGenerateCRLs(inStream: InputStream): util.Collection[_ <: CRL] = ???
  }
}