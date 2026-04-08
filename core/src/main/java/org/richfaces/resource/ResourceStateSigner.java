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

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.concurrent.atomic.AtomicReference;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * HMAC-SHA256 signer/verifier for the serialized resource-state that RichFaces puts into the
 * {@code do=} URL parameter of dynamic resource requests.
 *
 * <h3>Why this exists</h3>
 *
 * Historically, {@link DefaultResourceCodec} accepted any client-supplied {@code do=} value and
 * handed it to {@link ResourceUtils#decodeObjectData(String)}, which invokes Java object
 * deserialization via {@link org.richfaces.util.LookAheadObjectInputStream}. Even with a class
 * whitelist this is a dangerous attack surface (CVE-2013-2165, CVE-2018-12532, CVE-2018-12533,
 * CVE-2018-14667 were all reachable through this path). The correct defense-in-depth layer is to
 * ensure that an attacker cannot forge a {@code do=} payload in the first place: every serialized
 * state that leaves the server is accompanied by an HMAC signature computed with a secret that
 * the attacker does not possess, and every incoming request is rejected if the signature does not
 * match. Rejected requests never enter the deserialization pipeline.
 *
 * <h3>Key management</h3>
 *
 * The signing key is, in order of preference:
 * <ol>
 *   <li>The value of the {@code org.richfaces.resourceStateSigningKey} system property, decoded as
 *       Base64. This is the recommended configuration for clustered deployments -- every node must
 *       see the same key so resource URLs minted on one node verify on another. Provide at least
 *       32 random bytes (256 bits).</li>
 *   <li>A per-JVM random key generated once via {@link SecureRandom} on first use. This works for
 *       single-node deployments; the tradeoff is that a JVM restart invalidates all previously
 *       minted resource URLs.</li>
 * </ol>
 *
 * <h3>What is signed</h3>
 *
 * The signature covers {@code libraryName + "|" + resourceName + "|" + dataString + "|" + version}.
 * Including the resource identity prevents an attacker from swapping a signed {@code do=} state
 * from one resource onto another.
 *
 * @since 4.5.18
 */
public final class ResourceStateSigner {

    /** System property that, if set, overrides the generated per-JVM key. Value must be Base64. */
    public static final String SIGNING_KEY_PROPERTY = "org.richfaces.resourceStateSigningKey";

    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final int GENERATED_KEY_BYTES = 32;
    private static final String FIELD_SEPARATOR = "|";

    private static final AtomicReference<byte[]> KEY = new AtomicReference<byte[]>();

    private ResourceStateSigner() {
        // utility class
    }

    /**
     * Compute the signature for a (libraryName, resourceName, dataString, version) tuple and
     * return it as a URL-safe Base64 string (without padding).
     *
     * @return the signature, or {@code null} if {@code dataString} is {@code null} (nothing to sign)
     */
    public static String sign(String libraryName, String resourceName, String dataString, String version) {
        if (dataString == null) {
            return null;
        }
        byte[] mac = computeMac(buildPayload(libraryName, resourceName, dataString, version));
        return toUrlSafeBase64(mac);
    }

    /**
     * Verify a signature previously produced by {@link #sign}. Uses a constant-time comparison so
     * a failing verify does not leak timing information to an attacker probing for valid tags.
     *
     * @return {@code true} iff {@code providedSignature} matches the expected HMAC
     */
    public static boolean verify(String libraryName, String resourceName, String dataString,
        String version, String providedSignature) {
        if (dataString == null || providedSignature == null) {
            return false;
        }
        byte[] expected = computeMac(buildPayload(libraryName, resourceName, dataString, version));
        String expectedEncoded = toUrlSafeBase64(expected);
        // String.equals short-circuits on first differing char -- use MessageDigest.isEqual on the
        // raw bytes to keep the comparison constant-time.
        byte[] expectedBytes = expectedEncoded.getBytes();
        byte[] providedBytes = providedSignature.getBytes();
        return MessageDigest.isEqual(expectedBytes, providedBytes);
    }

    private static String buildPayload(String libraryName, String resourceName, String dataString,
        String version) {
        StringBuilder sb = new StringBuilder(
            (libraryName == null ? 0 : libraryName.length())
                + (resourceName == null ? 0 : resourceName.length())
                + dataString.length()
                + (version == null ? 0 : version.length())
                + 4);
        sb.append(libraryName == null ? "" : libraryName);
        sb.append(FIELD_SEPARATOR);
        sb.append(resourceName == null ? "" : resourceName);
        sb.append(FIELD_SEPARATOR);
        sb.append(dataString);
        sb.append(FIELD_SEPARATOR);
        sb.append(version == null ? "" : version);
        return sb.toString();
    }

    private static byte[] computeMac(String payload) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(getOrCreateKey(), HMAC_ALGORITHM));
            return mac.doFinal(payload.getBytes("UTF-8"));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("HmacSHA256 is required by the JCE spec but not available", e);
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException("UTF-8 is required by the JVM spec but not available", e);
        } catch (java.security.InvalidKeyException e) {
            throw new IllegalStateException("HMAC key could not be initialized", e);
        }
    }

    static byte[] getOrCreateKey() {
        byte[] current = KEY.get();
        if (current != null) {
            return current;
        }
        byte[] candidate = loadConfiguredKey();
        if (candidate == null) {
            candidate = new byte[GENERATED_KEY_BYTES];
            new SecureRandom().nextBytes(candidate);
        }
        if (KEY.compareAndSet(null, candidate)) {
            return candidate;
        }
        // Someone else won the race -- discard our candidate and return the installed one.
        return KEY.get();
    }

    private static byte[] loadConfiguredKey() {
        String configured;
        try {
            configured = System.getProperty(SIGNING_KEY_PROPERTY);
        } catch (SecurityException e) {
            // SecurityManager denied property read -- fall back to generated key silently.
            return null;
        }
        if (configured == null || configured.length() == 0) {
            return null;
        }
        try {
            byte[] decoded = java.util.Base64.getDecoder().decode(configured);
            if (decoded.length < 16) {
                // 128 bits is the absolute minimum for a usable HMAC key. Shorter keys are almost
                // certainly misconfiguration; fall back to the generated key instead of silently
                // accepting a weak one.
                return null;
            }
            return decoded;
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /** Exposed for tests that need to pin the key to a known value. Package-private on purpose. */
    static void setKeyForTesting(byte[] key) {
        KEY.set(key);
    }

    private static String toUrlSafeBase64(byte[] bytes) {
        // URL-safe Base64 without padding: the value can sit directly in a query string
        // without further percent-encoding.
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
