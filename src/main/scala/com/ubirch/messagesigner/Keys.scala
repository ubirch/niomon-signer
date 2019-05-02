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
import java.security.KeyStore
import java.security.KeyStore.PrivateKeyEntry

import com.typesafe.config.Config
import com.typesafe.scalalogging.StrictLogging
import com.ubirch.crypto.utils.Curve
import com.ubirch.crypto.{GeneratorKeyFactory, PrivKey}

class Keys(conf: Config) extends StrictLogging {
  private val pass = conf.getString("certificate.password").toCharArray
  private val entryAlias = conf.getString("certificate.entryAlias")
  private val privateKeyAlias = "pke_" + entryAlias

  lazy val privateKey: PrivKey = keyStore.getKey(privateKeyAlias, pass).asInstanceOf[PrivKey]

  lazy private val keyStore: KeyStore = {
    val ks = KeyStore.getInstance("jks")
    val fName = Paths.get(conf.getString("certificate.path"))

    if (Files.exists(fName)) {
      var ksFileInputStream: FileInputStream = new FileInputStream(fName.toFile)
      ks.load(ksFileInputStream, pass)
    } else {
      logger.error(s"key store not found: $fName")
      //throw new FileNotFoundException(s"key store not found: $fName")
    }

    // generate the key pair if not present
    if (!ks.containsAlias(entryAlias)) {
      logger.warn(s"no private key found: '$entryAlias, generating new private key")

      val privKey = GeneratorKeyFactory.getPrivKey(Curve.Ed25519)
      ks.setEntry(
        privateKeyAlias,
        new PrivateKeyEntry(privKey.getPrivateKey, Array()),
        new KeyStore.PasswordProtection(pass)
      )

      val fos = new FileOutputStream(fName.toFile)
      ks.store(fos, pass)
      fos.close()
    }

    ks
  }
}