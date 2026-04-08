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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Before;
import org.junit.Test;

/**
 * Tests for {@link ResourceStateSigner}.
 *
 * The signer is the guard that keeps attacker-supplied {@code do=} URL payloads out of Java
 * object deserialization in {@link DefaultResourceCodec#decodeResource}. These tests pin the
 * invariants that matter for that guard:
 *
 * <ul>
 *   <li>sign/verify round-trip for valid payloads;</li>
 *   <li>any mutation of the signed tuple (library, name, data, version) invalidates the signature;</li>
 *   <li>forged or missing signatures are rejected;</li>
 *   <li>null inputs do not produce a "valid" signature (no bypass via null-propagation).</li>
 * </ul>
 */
public class ResourceStateSignerTest {

    private static final byte[] FIXED_KEY = new byte[] {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
    };

    @Before
    public void pinKey() {
        // Pin the HMAC key so signatures are deterministic across runs and do not depend on
        // SecureRandom output or system properties that other tests may set.
        ResourceStateSigner.setKeyForTesting(FIXED_KEY);
    }

    @Test
    public void roundTrip() {
        String sig = ResourceStateSigner.sign("myLib", "img.jpg", "payload123", "4.5");
        assertNotNull(sig);
        assertTrue(ResourceStateSigner.verify("myLib", "img.jpg", "payload123", "4.5", sig));
    }

    @Test
    public void roundTripWithNullLibraryAndVersion() {
        String sig = ResourceStateSigner.sign(null, "img.jpg", "payload123", null);
        assertNotNull(sig);
        assertTrue(ResourceStateSigner.verify(null, "img.jpg", "payload123", null, sig));
    }

    @Test
    public void signNullDataReturnsNull() {
        // No data to sign means the serialized-state channel is unused; the codec must treat
        // this as "don't append a signature" rather than "sign an empty tuple".
        assertNull(ResourceStateSigner.sign("lib", "res", null, "v"));
    }

    @Test
    public void verifyNullSignatureIsRejected() {
        // A missing sig= parameter must never validate, even against null data.
        assertFalse(ResourceStateSigner.verify("lib", "res", "data", "v", null));
    }

    @Test
    public void verifyNullDataIsRejected() {
        String sig = ResourceStateSigner.sign("lib", "res", "data", "v");
        assertFalse(ResourceStateSigner.verify("lib", "res", null, "v", sig));
    }

    // --- Tamper detection: mutating any signed field must invalidate ---------------------------

    @Test
    public void tamperWithLibraryNameIsRejected() {
        String sig = ResourceStateSigner.sign("myLib", "img.jpg", "payload", "4.5");
        assertFalse(ResourceStateSigner.verify("otherLib", "img.jpg", "payload", "4.5", sig));
    }

    @Test
    public void tamperWithResourceNameIsRejected() {
        // This is the "move signed state from resource A to resource B" attack: the signature
        // must cover the resource identity so it cannot be replayed across resources.
        String sig = ResourceStateSigner.sign("lib", "mediaOutput", "payload", "4.5");
        assertFalse(ResourceStateSigner.verify("lib", "otherResource", "payload", "4.5", sig));
    }

    @Test
    public void tamperWithDataIsRejected() {
        String sig = ResourceStateSigner.sign("lib", "res", "originalPayload", "v");
        assertFalse(ResourceStateSigner.verify("lib", "res", "tamperedPayload", "v", sig));
    }

    @Test
    public void tamperWithVersionIsRejected() {
        String sig = ResourceStateSigner.sign("lib", "res", "payload", "4.5");
        assertFalse(ResourceStateSigner.verify("lib", "res", "payload", "4.6", sig));
    }

    @Test
    public void forgedRandomSignatureIsRejected() {
        assertFalse(ResourceStateSigner.verify("lib", "res", "payload", "v",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
    }

    @Test
    public void emptyStringSignatureIsRejected() {
        assertFalse(ResourceStateSigner.verify("lib", "res", "payload", "v", ""));
    }

    @Test
    public void truncatedSignatureIsRejected() {
        String sig = ResourceStateSigner.sign("lib", "res", "payload", "v");
        assertFalse(ResourceStateSigner.verify("lib", "res", "payload", "v", sig.substring(0, sig.length() - 1)));
    }

    @Test
    public void signatureIsUrlSafe() {
        // The signature must be URL-safe so it can go straight into a query string without
        // further percent-encoding. No '+' / '/' / '=' allowed.
        String sig = ResourceStateSigner.sign("lib", "res", "payload-with-special-chars+/=", "v");
        assertNotNull(sig);
        for (int i = 0; i < sig.length(); i++) {
            char c = sig.charAt(i);
            boolean allowed = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
                || (c >= '0' && c <= '9') || c == '-' || c == '_';
            assertTrue("signature contains non-url-safe char '" + c + "' in: " + sig, allowed);
        }
    }

    @Test
    public void signatureIsDeterministicForSameInput() {
        // HMAC is deterministic given a fixed key -- two signatures of the same tuple must match.
        String a = ResourceStateSigner.sign("lib", "res", "payload", "v");
        String b = ResourceStateSigner.sign("lib", "res", "payload", "v");
        assertEquals(a, b);
    }

    @Test
    public void signatureDiffersForDifferentInputs() {
        String a = ResourceStateSigner.sign("lib", "res", "payloadA", "v");
        String b = ResourceStateSigner.sign("lib", "res", "payloadB", "v");
        assertFalse("signatures of different payloads must not collide", a.equals(b));
    }
}
