/*
 * The MIT License
 *
 * Copyright 2016 Romain Cambier <me@romaincambier.be>.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package be.romaincambier.lorawan;

import be.romaincambier.lorawan.exceptions.MalformedPacketException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author cambierr
 */
public class JoinAcceptPayload implements FRMPayload {

    private final MacPayload mac;
    private final byte[] payload;

    protected JoinAcceptPayload(MacPayload _mac, ByteBuffer _raw) throws MalformedPacketException {
        mac = _mac;
        if (_raw.remaining() < 12) {
            throw new MalformedPacketException("could not read joinAcceptPayload");
        }
        payload = new byte[_raw.remaining() - 4];
        _raw.get(payload);
    }

    @Override
    public int length() {
        return payload.length;
    }

    @Override
    public void binarize(ByteBuffer _bb) {
        _bb.put(payload);
    }

    public MacPayload getMac() {
        return mac;
    }

    public JoinAcceptClearPayload getClearPayload(byte[] _appKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        if (_appKey == null) {
            throw new RuntimeException("Missing appKey");
        }
        if (_appKey.length != 16) {
            throw new IllegalArgumentException("Invalid appKey");
        }
        ByteBuffer a = ByteBuffer.allocate(4 + length());
        a.order(ByteOrder.LITTLE_ENDIAN);
        a.put(payload);
        a.put(mac.getPhyPayload().getMic());
        try {
            Key aesKey = new SecretKeySpec(_appKey, "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, aesKey);
            byte[] s = cipher.doFinal(a.array());
            return new JoinAcceptClearPayload(s);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
            throw new RuntimeException("Could not decrypt payload", ex);
        }
    }

    public byte[] computeMic(byte[] _appKey) {
        if (_appKey == null) {
            throw new RuntimeException("Missing appKey");
        }
        if (_appKey.length != 16) {
            throw new IllegalArgumentException("Invalid appKey");
        }
        //size = mhdr + length()
        ByteBuffer body = ByteBuffer.allocate(1 + length());
        body.order(ByteOrder.LITTLE_ENDIAN);
        body.put(mac.getPhyPayload().getMHDR());
        binarize(body);

        AesCmac aesCmac;
        try {
            aesCmac = new AesCmac();
            aesCmac.init(new SecretKeySpec(_appKey, "AES"));
            aesCmac.updateBlock(body.array());
            return Arrays.copyOfRange(aesCmac.doFinal(), 0, 4);
        } catch (NoSuchAlgorithmException | InvalidKeyException | InvalidAlgorithmParameterException ex) {
            throw new RuntimeException("Could not compute AesCmac", ex);
        }
    }

    public static class JoinAcceptClearPayload implements Binarizable {

        private final byte[] appNonce = new byte[3];
        private final byte[] netId = new byte[3];
        private final byte[] devAddr = new byte[4];
        private final byte dlSettings;
        private final byte rxDelay;
        private final byte[] cfList;

        private JoinAcceptClearPayload(byte[] _raw) {
            ByteBuffer bb = ByteBuffer.wrap(_raw);
            bb.get(appNonce);
            bb.get(netId);
            bb.get(devAddr);
            dlSettings = bb.get();
            rxDelay = bb.get();
            cfList = new byte[bb.remaining() - 4];
            bb.get(cfList);
        }

        public byte[] getAppNonce() {
            return appNonce;
        }

        public byte[] getNetId() {
            return netId;
        }

        public byte[] getDevAddr() {
            return devAddr;
        }

        public byte getDlSettings() {
            return dlSettings;
        }

        public byte getRxDelay() {
            return rxDelay;
        }

        public byte[] getCfList() {
            return cfList;
        }

        @Override
        public void binarize(ByteBuffer _bb) {
            _bb.put(appNonce);
            _bb.put(netId);
            _bb.put(devAddr);
            _bb.put(dlSettings);
            _bb.put(rxDelay);
            _bb.put(cfList);
        }

        @Override
        public int length() {
            return appNonce.length + netId.length + devAddr.length + 1 + 1 + cfList.length;
        }
    }

}
