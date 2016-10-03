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

/**
 *
 * @author cambierr
 */
public class FHDR implements Binarizable {

    private final byte[] devAddr = new byte[4];
    private final byte fCtrl;
    private final short fCnt;
    private final byte[] fOpts;

    protected FHDR(ByteBuffer _raw) throws MalformedPacketException {
        if (_raw.remaining() < 7) {
            throw new MalformedPacketException("can not read fhdr");
        }
        _raw.get(devAddr);
        fCtrl = _raw.get();
        fCnt = _raw.getShort();
        fOpts = new byte[fCtrl & 0xf];
        if (_raw.remaining() < fOpts.length) {
            throw new MalformedPacketException("can not read fOpts");
        }
        _raw.get(fOpts);
    }

    @Override
    public void binarize(ByteBuffer _bb) {
        _bb.put(devAddr);
        _bb.put(fCtrl);
        _bb.putShort(fCnt);
        _bb.put(fOpts);
    }

    public byte[] getDevAddr() {
        return devAddr;
    }

    public byte getfCtrl() {
        return fCtrl;
    }

    public short getfCnt() {
        return fCnt;
    }

    public byte[] getfOpts() {
        return fOpts;
    }

    @Override
    public int length() {
        return devAddr.length + 1 + 2 + fOpts.length;
    }
}
