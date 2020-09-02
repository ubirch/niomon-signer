package com.ubirch.protocol.codec;

import com.fasterxml.jackson.databind.node.TextNode;
import com.ubirch.protocol.ProtocolException;
import com.ubirch.protocol.ProtocolMessage;
import com.ubirch.protocol.ProtocolSigner;
import org.msgpack.core.MessagePacker;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.util.Base64;

public class MsgPackProtocolEncoderExtended extends MsgPackProtocolEncoder {

    private static final MsgPackProtocolEncoderExtended instance = new MsgPackProtocolEncoderExtended();

    final private MsgPackProtocolSigning protocolSigning = new MsgPackProtocolSigning() {
        @Override
        public void payloadConsumer(MessagePacker packer, ProtocolMessage pm, ByteArrayOutputStream out) throws IOException {
            if (pm.getPayload() instanceof TextNode) {
                // write the payload
                try {
                    //We try to decode from base64 as this is what is expected when it is binary
                    byte[] bytes = Base64.getDecoder().decode(pm.getPayload().asText());
                    packer.packBinaryHeader(16).addPayload(bytes);
                } catch (Exception e) {
                    super.payloadConsumer(packer, pm, out);
                }
            } else {
                super.payloadConsumer(packer, pm, out);
            }
        }
    };

    public static MsgPackProtocolEncoderExtended getEncoder() {
        return instance;
    }

    @Override
    public byte[] encode(ProtocolMessage pm, ProtocolSigner signer) throws ProtocolException, SignatureException {
        if (pm == null || signer == null) {
            throw new IllegalArgumentException("message or signer null");
        }

        try {
            return encode(protocolSigning.sign(pm, signer));
        } catch (InvalidKeyException e) {
            throw new ProtocolException("invalid key", e);
        } catch (IOException e) {
            throw new ProtocolException("msgpack encoding failed", e);
        } catch (NullPointerException e) {
            throw new ProtocolException("msgpack encoding failed: field null?", e);
        }
    }

}
