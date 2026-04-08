/*
 * JBoss, Home of Professional Open Source
 * Copyright 2013, Red Hat, Inc. and individual contributors
 * by the @authors tag. See the copyright.txt in the distribution for a
 * full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.richfaces.resource;

import static org.easymock.EasyMock.expect;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.HashMap;
import java.util.Map;

import javax.faces.context.ExternalContext;
import javax.faces.context.FacesContext;

import org.easymock.classextension.EasyMock;
import org.junit.Before;
import org.junit.Test;

/**
 * Security tests for {@link DefaultResourceCodec}: the codec must only hand a
 * {@code do=}-encoded payload to Java deserialization if the HMAC {@code sig=} parameter matches.
 *
 * <p>Covers the CVE-2018-12532 entry point. The pre-patch codec accepted any {@code do=} value
 * and fed it to {@link ResourceUtils#decodeObjectData(String)}. The patched codec:
 * <ul>
 *     <li>appends a valid {@code sig=} for every serialized state it emits;</li>
 *     <li>accepts an incoming {@code do=} only if {@code sig=} matches the expected HMAC;</li>
 *     <li>silently drops the serialized payload otherwise (so downstream code behaves as if no
 *         state was supplied, rather than reaching {@link java.io.ObjectInputStream}).</li>
 * </ul>
 */
public class DefaultResourceCodecSecurityTest {

    private static final byte[] FIXED_KEY = new byte[] {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88,
        (byte) 0x99, (byte) 0xaa, (byte) 0xbb, (byte) 0xcc, (byte) 0xdd, (byte) 0xee, (byte) 0xff, 0x00,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
    };

    private DefaultResourceCodec codec;

    @Before
    public void setUp() {
        ResourceStateSigner.setKeyForTesting(FIXED_KEY);
        codec = new DefaultResourceCodec();
    }

    // ---------------------------------------------------------------------------------------
    // Encoding: every serialized resource URL must carry a sig= parameter.
    // ---------------------------------------------------------------------------------------

    @Test
    public void encodedSerializedUrlContainsSignature() {
        String url = codec.encodeResource("myLib", "dynamic.jpg", "serializedPayload", true, "4.5");
        assertTrue("serialized URL must contain sig=: " + url, url.contains("&sig=") || url.contains("?sig="));
        assertTrue("serialized URL must still contain do=: " + url, url.contains("do=serializedPayload"));
    }

    @Test
    public void encodedByteArrayUrlDoesNotContainSignature() {
        // db= payloads are compressed bytes, never fed to ObjectInputStream -- no signature needed.
        String url = codec.encodeResource("myLib", "static.png", "bytesPayload", false, "4.5");
        assertFalse("byte-array URL must not contain sig=: " + url, url.contains("sig="));
    }

    @Test
    public void encodedUrlWithoutDataHasNoSignature() {
        String url = codec.encodeResource("myLib", "plain.png", null, false, "4.5");
        assertFalse(url.contains("sig="));
    }

    // ---------------------------------------------------------------------------------------
    // Decoding: round-trip succeeds; forgery, truncation and replay fail.
    // ---------------------------------------------------------------------------------------

    @Test
    public void decodeAcceptsValidlySignedState() {
        String signature = ResourceStateSigner.sign("myLib", "dynamic.jpg", "serializedPayload", "4.5");
        assertNotNull(signature);

        ResourceRequestData data = decode("dynamic.jpg", params()
            .with("ln", "myLib")
            .with("v", "4.5")
            .with("do", "serializedPayload")
            .with("sig", signature));

        DefaultCodecResourceRequestData asDefault = (DefaultCodecResourceRequestData) data;
        assertTrue("validly signed state must be marked serialized", asDefault.isDataSerialized());
        assertEquals("serializedPayload", asDefault.getDataString());
    }

    @Test
    public void decodeRejectsMissingSignature() {
        // Classic CVE-2018-12532 attempt: attacker POSTs a do= without any sig=.
        ResourceRequestData data = decode("MediaOutputResource", params()
            .with("do", "attackerPayload"));

        DefaultCodecResourceRequestData asDefault = (DefaultCodecResourceRequestData) data;
        assertFalse("unsigned serialized payload must not be marked serialized",
            asDefault.isDataSerialized());
        assertNull("unsigned serialized payload must be dropped", asDefault.getDataString());
        assertNull("getData() must return null when the payload was dropped", asDefault.getData());
    }

    @Test
    public void decodeRejectsForgedSignature() {
        ResourceRequestData data = decode("MediaOutputResource", params()
            .with("do", "attackerPayload")
            .with("sig", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));

        assertNull(((DefaultCodecResourceRequestData) data).getDataString());
    }

    @Test
    public void decodeRejectsSignatureFromDifferentResource() {
        // Attacker lifts a valid signed state from 'otherResource' and replays it against
        // 'MediaOutputResource'. Because the resource name is part of the signed tuple, this
        // replay must fail even though the signature was genuinely produced by the server.
        String sigForOther = ResourceStateSigner.sign("myLib", "otherResource", "validPayload", "4.5");

        ResourceRequestData data = decode("MediaOutputResource", params()
            .with("ln", "myLib")
            .with("v", "4.5")
            .with("do", "validPayload")
            .with("sig", sigForOther));

        assertNull("cross-resource signature replay must be rejected",
            ((DefaultCodecResourceRequestData) data).getDataString());
    }

    @Test
    public void decodeRejectsSignatureAfterPayloadTamper() {
        String sig = ResourceStateSigner.sign("lib", "res.jpg", "original", "v");

        ResourceRequestData data = decode("res.jpg", params()
            .with("ln", "lib")
            .with("v", "v")
            .with("do", "tamperedPayload")
            .with("sig", sig));

        assertNull(((DefaultCodecResourceRequestData) data).getDataString());
    }

    @Test
    public void decodeLeavesByteArrayDataUntouched() {
        // db= (byte-array) path is independent of the signing scheme; a request without do=
        // should still read db= normally.
        ResourceRequestData data = decode("sprite.png", params()
            .with("db", "bytesPayload"));

        DefaultCodecResourceRequestData asDefault = (DefaultCodecResourceRequestData) data;
        assertFalse(asDefault.isDataSerialized());
        assertEquals("bytesPayload", asDefault.getDataString());
    }

    // ---------------------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------------------

    private ResourceRequestData decode(String requestPath, Params params) {
        FacesContext facesContext = EasyMock.createMock(FacesContext.class);
        ExternalContext externalContext = EasyMock.createMock(ExternalContext.class);
        expect(facesContext.getExternalContext()).andReturn(externalContext).anyTimes();
        expect(externalContext.getRequestParameterMap()).andReturn(params.map).anyTimes();
        EasyMock.replay(facesContext, externalContext);
        return codec.decodeResource(facesContext, requestPath);
    }

    private static Params params() {
        return new Params();
    }

    private static final class Params {
        final Map<String, String> map = new HashMap<String, String>();

        Params with(String key, String value) {
            map.put(key, value);
            return this;
        }
    }
}
