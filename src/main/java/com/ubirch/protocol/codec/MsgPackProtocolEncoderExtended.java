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
            // To be able to return the payload as just bytes and not as base64 values, we have to
            // explicitly try to decode and pack the data in the msgpack.
            // There seems to be a limitation with the way json4s handles binary nodes.
            // https://gitlab.com/ubirch/ubirch-kafka-envelope/-/blob/master/src/main/scala/com/ubirch/kafka/package.scala#L166
            if (pm.getPayload() instanceof TextNode) {
                // write the payload
                try {
                    byte[] bytes = Base64.getDecoder().decode(pm.getPayload().asText());
                    packer.packBinaryHeader(bytes.length).addPayload(bytes);
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
