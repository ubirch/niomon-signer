package com.ubirch.messagesigner

import java.io.{FileInputStream, FileOutputStream}
import java.nio.file.Files
import java.security.{KeyPairGenerator, KeyStore}
import java.security.KeyStore.{PrivateKeyEntry, TrustedCertificateEntry}

import net.i2p.crypto.eddsa.{EdDSAKey, EdDSAPrivateKey, EdDSAPublicKey}

object Keys {
  private val privateKeyAlias = "pke_" + Config.keyStoreEntryAlias

  lazy private val keyStore = {
    val ks = KeyStore.getInstance("jks")
    var ksFileInputStream: FileInputStream = null
    val fName = Config.keyStoreFilename
    val ksPass = Config.keyStorePassword
    if (Files.exists(fName)) ksFileInputStream = new FileInputStream(fName.toFile)
    ks.load(ksFileInputStream, ksPass.toCharArray)

    // generate the key pair if not present
    if (!ks.containsAlias(Config.keyStoreEntryAlias)) {
      val kPair = KeyPairGenerator.getInstance(EdDSAKey.KEY_ALGORITHM).generateKeyPair()
      val cert = new EdDSACertificate(kPair.getPublic.asInstanceOf[EdDSAPublicKey])

      ks.setEntry(Config.keyStoreEntryAlias, new TrustedCertificateEntry(cert), null)
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

  lazy val privateKey: EdDSAPrivateKey = keyStore.getKey(privateKeyAlias, Config.keyStorePassword.toCharArray)
    .asInstanceOf[EdDSAPrivateKey]
}
