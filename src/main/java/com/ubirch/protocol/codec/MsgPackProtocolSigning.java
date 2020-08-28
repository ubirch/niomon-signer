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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ubirch.protocol.ProtocolException;
import com.ubirch.protocol.ProtocolMessage;
import com.ubirch.protocol.ProtocolSigner;
import org.msgpack.core.MessagePack;
import org.msgpack.core.MessagePacker;
import org.msgpack.jackson.dataformat.MessagePackFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.SignatureException;

public class MsgPackProtocolSigning {

    private static MessagePack.PackerConfig config = new MessagePack.PackerConfig().withStr8FormatSupport(false);

    final ByteArrayOutputStream out;
    final MessagePacker packer;
    final ProtocolMessage pm;
    final ProtocolSigner signer;

    public MsgPackProtocolSigning(ProtocolMessage pm, ProtocolSigner signer) {
        this.pm = pm;
        this.signer = signer;
        this.out = new ByteArrayOutputStream(255);
        this.packer = config.newPacker(out);
    }

    public void version() throws IOException {
        packer.packInt(pm.getVersion());
    }

    public void UUID() throws IOException {
        packer.packBinaryHeader(16).addPayload(UUIDUtil.uuidToBytes(pm.getUUID()));
    }

    public void chain() throws IOException {
        switch (pm.getVersion()) {
            case ProtocolMessage.CHAINED:
                packer.packBinaryHeader(64);
                byte[] chainSignature = pm.getChain();
                if (chainSignature == null) {
                    packer.addPayload(new byte[64]);
                } else {
                    packer.addPayload(chainSignature);
                }
                break;
            case ProtocolMessage.SIGNED:
                break;
            default:
                throw new ProtocolException(String.format("unknown protocol version: 0x%x", pm.getVersion()));
        }
    }

    public void hint() throws IOException {
        packer.packInt(pm.getHint());
    }

    public void payload() throws IOException {
        ObjectMapper mapper = new ObjectMapper(new MessagePackFactory());
        mapper.writeValue(out, pm.getPayload());
    }

    public ProtocolMessage sign() throws IOException, SignatureException, InvalidKeyException {
        packer.packArrayHeader(5 + (pm.getVersion() & 0x0f) - 2);
        version();
        UUID();
        chain();
        hint();
        packer.flush(); // make sure everything is in the byte buffer
        payload();
        packer.close(); // also closes out

        byte[] dataToSign = out.toByteArray();
        byte[] signature = signer.sign(pm.getUUID(), dataToSign, 0, dataToSign.length);
        pm.setSigned(dataToSign);
        pm.setSignature(signature);
        return pm;
    }

}
