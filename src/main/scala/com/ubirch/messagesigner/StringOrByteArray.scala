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

import com.ubirch.niomon.util.KafkaPayload

// This may seem a little useless. That's because it mostly is. It's a leftover from an earlier refactoring.
object StringOrByteArray {
  type StringOrByteArray = Either[Array[Byte], String]

  def apply(inner: String): StringOrByteArray = Right(inner)

  def apply(inner: Array[Byte]): StringOrByteArray = Left(inner)

  implicit val stringOrByteArrayKafkaPayload: KafkaPayload[StringOrByteArray] = KafkaPayload.tryBothEitherKafkaPayload
}

