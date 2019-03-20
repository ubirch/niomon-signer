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

import java.io.{FileInputStream, FileOutputStream}
import java.nio.file.{Files, Paths}
import java.security.KeyStore.{PrivateKeyEntry, TrustedCertificateEntry}
import java.security.{KeyPairGenerator, KeyStore}

import com.typesafe.config.Config
import net.i2p.crypto.eddsa.{EdDSAKey, EdDSAPrivateKey, EdDSAPublicKey}

class Keys(conf: Config) {
  private val pass = conf.getString("certificate.password").toCharArray
  private val entryAlias = conf.getString("certificate.entryAlias")
  private val privateKeyAlias = "pke_" + entryAlias

  lazy val privateKey: EdDSAPrivateKey = keyStore.getKey(privateKeyAlias, pass)
    .asInstanceOf[EdDSAPrivateKey]
  lazy private val keyStore = {
    val ks = KeyStore.getInstance("jks")
    var ksFileInputStream: FileInputStream = null // scalastyle:off null
    val fName = Paths.get(conf.getString("certificate.path"))
    if (Files.exists(fName)) ksFileInputStream = new FileInputStream(fName.toFile)
    ks.load(ksFileInputStream, pass)

    // generate the key pair if not present
    if (!ks.containsAlias(entryAlias)) {
      val kPair = KeyPairGenerator.getInstance(EdDSAKey.KEY_ALGORITHM).generateKeyPair()
      val cert = new EdDSACertificate(kPair.getPublic.asInstanceOf[EdDSAPublicKey])

      ks.setEntry(entryAlias, new TrustedCertificateEntry(cert), null) // scalastyle:off null
      ks.setEntry(
        privateKeyAlias,
        new PrivateKeyEntry(kPair.getPrivate, Array(cert)),
        new KeyStore.PasswordProtection(pass)
      )

      val fos = new FileOutputStream(fName.toFile)
      ks.store(fos, pass)
      fos.close()
    }

    ks
  }
}
