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

/**
 *
 * @author cambierr
 */
public class PhyPayload implements Binarizable {

    private final byte mhdr;
    private final MacPayload macPayload;
    private final byte[] mic = new byte[4];

    private PhyPayload(ByteBuffer _raw) throws MalformedPacketException {
        _raw.order(ByteOrder.LITTLE_ENDIAN);
        if (_raw.remaining() < 1) {
            throw new MalformedPacketException("can not read mhdr");
        }
        mhdr = _raw.get();
        macPayload = new MacPayload(this, _raw);
        if (_raw.remaining() < 4) {
            throw new MalformedPacketException("can not read mic");
        }
        _raw.get(mic);
    }

    public static PhyPayload parse(ByteBuffer _raw) throws MalformedPacketException {
        return new PhyPayload(_raw);
    }

    @Override
    public void binarize(ByteBuffer _bb) throws MalformedPacketException {
        _bb.order(ByteOrder.LITTLE_ENDIAN);
        _bb.put(mhdr);
        macPayload.binarize(_bb);
        _bb.put(mic);
    }

    public MType getMType() throws MalformedPacketException {
        return MType.from(mhdr);
    }

    public MajorVersion getMajorVersion() throws MalformedPacketException {
        return MajorVersion.from(mhdr);
    }

    public byte getMHDR() {
        return mhdr;
    }

    public MacPayload getMacPayload() {
        return macPayload;
    }

    public byte[] getMic() {
        return mic;
    }

    @Override
    public int length() {
        return 1 + macPayload.length() + 4;
    }

}
