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

package com.ubirch.protocol.codec;

import com.fasterxml.jackson.databind.node.TextNode;
import com.ubirch.protocol.ProtocolException;
import com.ubirch.protocol.ProtocolMessage;
import com.ubirch.protocol.ProtocolSigner;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.util.Base64;

public class MsgPackProtocolEncoderExtended extends MsgPackProtocolEncoder {

    private static final MsgPackProtocolEncoderExtended instance = new MsgPackProtocolEncoderExtended();

    public static MsgPackProtocolEncoderExtended getEncoder() {
        return instance;
    }

    @Override
    public byte[] encode(ProtocolMessage pm, ProtocolSigner signer) throws ProtocolException, SignatureException {
        if (pm == null || signer == null) {
            throw new IllegalArgumentException("message or signer null");
        }

        try {
            MsgPackProtocolSigning protocolSigning = new MsgPackProtocolSigning(pm, signer) {
                @Override
                public void payload() throws IOException {
                    if (pm.getPayload() instanceof TextNode) {
                        // write the payload
                        byte[] bytes = Base64.getDecoder().decode(pm.getPayload().asText());
                        packer.packBinaryHeader(16).addPayload(bytes);
                    } else {
                        super.payload();
                    }
                }
            };
            return encode(protocolSigning.sign());
        } catch (InvalidKeyException e) {
            throw new ProtocolException("invalid key", e);
        } catch (IOException e) {
            throw new ProtocolException("msgpack encoding failed", e);
        } catch (NullPointerException e) {
            throw new ProtocolException("msgpack encoding failed: field null?", e);
        }
    }

}
