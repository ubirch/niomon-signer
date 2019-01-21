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
import java.nio.file.Files
import java.security.KeyStore.{PrivateKeyEntry, TrustedCertificateEntry}
import java.security.{KeyPairGenerator, KeyStore}

import net.i2p.crypto.eddsa.{EdDSAKey, EdDSAPrivateKey, EdDSAPublicKey}

object Keys {
  lazy val privateKey: EdDSAPrivateKey = keyStore.getKey(privateKeyAlias, Config.keyStorePassword.toCharArray)
    .asInstanceOf[EdDSAPrivateKey]
  lazy private val keyStore = {
    val ks = KeyStore.getInstance("jks")
    var ksFileInputStream: FileInputStream = null // scalastyle:off null
    val fName = Config.keyStoreFilename
    val ksPass = Config.keyStorePassword
    if (Files.exists(fName)) ksFileInputStream = new FileInputStream(fName.toFile)
    ks.load(ksFileInputStream, ksPass.toCharArray)

    // generate the key pair if not present
    if (!ks.containsAlias(Config.keyStoreEntryAlias)) {
      val kPair = KeyPairGenerator.getInstance(EdDSAKey.KEY_ALGORITHM).generateKeyPair()
      val cert = new EdDSACertificate(kPair.getPublic.asInstanceOf[EdDSAPublicKey])

      ks.setEntry(Config.keyStoreEntryAlias, new TrustedCertificateEntry(cert), null) // scalastyle:off null
      ks.setEntry(
        privateKeyAlias,
        new PrivateKeyEntry(kPair.getPrivate, Array(cert)),
        new KeyStore.PasswordProtection(ksPass.toCharArray)
      )

      val fos = new FileOutputStream(fName.toFile)
      ks.store(fos, ksPass.toCharArray)
      fos.close()
    }

    ks
  }
  private val privateKeyAlias = "pke_" + Config.keyStoreEntryAlias
}
