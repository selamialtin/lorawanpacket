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
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author cambierr
 */
public class JoinRequestPayload implements FRMPayload {

    private final MacPayload mac;
    private final byte[] appEUI = new byte[8];
    private final byte[] devEUI = new byte[8];
    private final byte[] devNonce = new byte[2];

    protected JoinRequestPayload(MacPayload _mac, ByteBuffer _raw) throws MalformedPacketException {
        mac = _mac;
        if (_raw.remaining() < 18) {
            throw new MalformedPacketException("could not read joinRequestPayload");
        }
        _raw.get(appEUI);
        _raw.get(devEUI);
        _raw.get(devNonce);
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

    @Override
    public int length() {
        return 18;
    }

    @Override
    public void binarize(ByteBuffer _bb) {
        _bb.order(ByteOrder.LITTLE_ENDIAN);
        _bb.put(appEUI);
        _bb.put(devEUI);
        _bb.put(devNonce);
    }

    public MacPayload getMac() {
        return mac;
    }

    public byte[] getAppEUI() {
        return appEUI;
    }

    public byte[] getDevEUI() {
        return devEUI;
    }

    public byte[] getDevNonce() {
        return devNonce;
    }

}
