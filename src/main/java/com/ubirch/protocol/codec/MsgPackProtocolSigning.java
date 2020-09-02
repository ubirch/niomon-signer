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
import java.util.function.BiFunction;
import java.util.function.Function;

public class MsgPackProtocolSigning {

    private static final MessagePack.PackerConfig config = new MessagePack.PackerConfig().withStr8FormatSupport(false);

    public MsgPackProtocolSigning() { }

    public void versionConsumer(MessagePacker packer, ProtocolMessage pm) throws IOException {
        packer.packInt(pm.getVersion());
    }

    public void uuidConsumer(MessagePacker packer, ProtocolMessage pm) throws IOException {
        packer.packBinaryHeader(16).addPayload(UUIDUtil.uuidToBytes(pm.getUUID()));
    }

    public void chainConsumer(MessagePacker packer, ProtocolMessage pm) throws IOException {
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

    public void hintConsumer(MessagePacker packer, ProtocolMessage pm) throws IOException {
        packer.packInt(pm.getHint());
    }

    public void payloadConsumer(MessagePacker packer, ProtocolMessage pm, ByteArrayOutputStream out) throws IOException {
        ObjectMapper mapper = new ObjectMapper(new MessagePackFactory());
        mapper.writeValue(out, pm.getPayload());
    }

    public ProtocolMessage sign(ProtocolMessage pm, ProtocolSigner signer) throws IOException, SignatureException, InvalidKeyException {
        //We prepare the streams and the packer
        ByteArrayOutputStream out = new ByteArrayOutputStream(255);
        MessagePacker packer = config.newPacker(out);
        packer.packArrayHeader(5 + (pm.getVersion() & 0x0f) - 2);

        //We build a stream based on the proper order for the Protocol Message
        versionConsumer(packer, pm);
        uuidConsumer(packer, pm);
        chainConsumer(packer, pm);
        hintConsumer(packer, pm);
        packer.flush(); // make sure everything is in the byte buffer
        payloadConsumer(packer, pm, out);
        packer.close(); // also closes out

        //We sign the bytes
        byte[] dataToSign = out.toByteArray();
        byte[] signature = signer.sign(pm.getUUID(), dataToSign, 0, dataToSign.length);

        //We set the values into the protocol message
        pm.setSigned(dataToSign);
        pm.setSignature(signature);
        return pm;
    }

}
