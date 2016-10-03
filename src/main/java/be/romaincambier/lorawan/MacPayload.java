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
import java.lang.reflect.InvocationTargetException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 *
 * @author cambierr
 */
public class MacPayload implements Binarizable {

    private final FHDR fhdr;
    private final byte fPort;
    private final FRMPayload payload;
    private final PhyPayload phy;

    protected MacPayload(PhyPayload _phy, ByteBuffer _raw) throws MalformedPacketException {
        phy = _phy;
        fhdr = new FHDR(_raw);
        fPort = _raw.get();
        Class<? extends FRMPayload> mapper = phy.getMType().getMapper();
        try {
            payload = mapper.getDeclaredConstructor(MacPayload.class, ByteBuffer.class).newInstance(this, _raw);
        } catch (NoSuchMethodException | SecurityException | InstantiationException | IllegalAccessException | IllegalArgumentException | InvocationTargetException ex) {
            throw new RuntimeException("Could not create FRMPayload", ex);
        }
    }

    @Override
    public void binarize(ByteBuffer _bb) throws MalformedPacketException {
        _bb.order(ByteOrder.LITTLE_ENDIAN);
        fhdr.binarize(_bb);
        if (payload != null) {
            _bb.put(fPort);
            payload.binarize(_bb);
        }
    }

    public FHDR getFhdr() {
        return fhdr;
    }

    public byte getfPort() {
        return fPort;
    }

    public FRMPayload getPayload() {
        return payload;
    }

    public PhyPayload getPhyPayload() {
        return phy;
    }

    @Override
    public int length() {
        return fhdr.length() + ((payload == null) ? 0 : (1 + payload.length()));
    }

}
