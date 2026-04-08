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

import java.util.Map;

import javax.faces.context.FacesContext;

import org.richfaces.log.Logger;
import org.richfaces.log.RichfacesLogger;

public final class DefaultResourceCodec implements ResourceCodec {
    private static final Logger LOGGER = RichfacesLogger.RESOURCE.getLogger();

    private static final String VERSION_PARAM = "v";
    private static final String DATA_BYTES_ARRAY_PARAM = "db";
    private static final String DATA_OBJECT_PARAM = "do";
    private static final String LIBRARY_NAME_PARAM = "ln";
    /**
     * HMAC signature parameter guarding the {@code do=} (serialized state) payload.
     * See {@link ResourceStateSigner} -- without a valid signature the {@code do=} value is
     * never handed to Java deserialization, which closes the CVE-2018-12532 / CVE-2018-14667
     * attack surface.
     */
    private static final String SIGNATURE_PARAM = "sig";

    String encodeResource(DefaultCodecResourceRequestData data) {
        return encodeResource(data.getLibraryName(), data.getResourceName(), data.getDataString(), data.isDataSerialized(),
            data.getVersion());
    }

    String encodeResource(String libraryName, String resourceName, String encodedResourceData, boolean dataIsSerialized,
        String resourceVersion) {

        boolean parameterAppended = false;

        StringBuilder sb = new StringBuilder();
        sb.append(resourceName);

        if (resourceVersion != null && resourceVersion.length() != 0) {
            if (!parameterAppended) {
                sb.append('?');
                parameterAppended = true;
            }

            sb.append(VERSION_PARAM);
            sb.append('=');
            sb.append(ResourceUtils.encodeURIQueryPart(resourceVersion));
        }

        if (encodedResourceData != null && encodedResourceData.length() != 0) {
            if (!parameterAppended) {
                sb.append('?');
                parameterAppended = true;
            } else {
                sb.append('&');
            }

            sb.append(dataIsSerialized ? DATA_OBJECT_PARAM : DATA_BYTES_ARRAY_PARAM);
            sb.append('=');
            sb.append(ResourceUtils.encodeURIQueryPart(encodedResourceData));
        }

        if (libraryName != null && libraryName.length() != 0) {
            if (!parameterAppended) {
                sb.append('?');
                parameterAppended = true;
            } else {
                sb.append('&');
            }

            sb.append(LIBRARY_NAME_PARAM);
            sb.append('=');
            sb.append(ResourceUtils.encodeURIQueryPart(libraryName));
        }

        // Only serialized payloads need signing. Byte-array payloads go through the compressed
        // bytes channel (db=) and are not deserialized into arbitrary Java objects, so the HMAC
        // guard is unnecessary there.
        if (dataIsSerialized && encodedResourceData != null && encodedResourceData.length() != 0) {
            String signature = ResourceStateSigner.sign(libraryName, resourceName, encodedResourceData, resourceVersion);
            if (signature != null) {
                sb.append(parameterAppended ? '&' : '?');
                parameterAppended = true;
                sb.append(SIGNATURE_PARAM);
                sb.append('=');
                sb.append(signature);
            }
        }

        return sb.toString();
    }

    public String encodeResourceRequestPath(FacesContext context, String libraryName, String resourceName, Object resourceData,
        String resourceVersion) {
        String encodedDataString = null;
        boolean dataIsSerialized = false;
        if (resourceData != null) {
            if (resourceData instanceof byte[]) {
                encodedDataString = ResourceUtils.encodeBytesData((byte[]) resourceData);
            } else {
                encodedDataString = ResourceUtils.encodeObjectData(resourceData);
                dataIsSerialized = true;
            }
        }

        return ResourceHandlerImpl.RICHFACES_RESOURCE_IDENTIFIER
            + encodeResource(libraryName, resourceName, encodedDataString, dataIsSerialized, resourceVersion);
    }

    public String encodeJSFMapping(FacesContext context, String resourcePath) {
        return ResourceUtils.encodeJSFURL(context, resourcePath);
    }

    public ResourceRequestData decodeResource(FacesContext context, String requestPath) {
        Map<String, String> params = context.getExternalContext().getRequestParameterMap();
        DefaultCodecResourceRequestData data = new DefaultCodecResourceRequestData(this);
        data.setResourceName(requestPath);
        data.setLibraryName(params.get(LIBRARY_NAME_PARAM));
        data.setVersion(params.get(VERSION_PARAM));

        String objectDataString = params.get(DATA_OBJECT_PARAM);
        if (objectDataString != null) {
            // SECURITY: a serialized-state parameter is only trusted if it carries a valid HMAC
            // signature produced by this server. Without a matching signature we drop the payload
            // entirely -- the downstream code will then see no data and fail the request rather
            // than reaching ResourceUtils.decodeObjectData() / ObjectInputStream.readObject().
            // This closes the deserialization entry point exploited by CVE-2018-12532 and the
            // RichFaces EL-injection RCE chain (CVE-2013-2165, CVE-2018-14667).
            String providedSignature = params.get(SIGNATURE_PARAM);
            boolean signatureValid = ResourceStateSigner.verify(
                data.getLibraryName(), requestPath, objectDataString, data.getVersion(), providedSignature);
            if (signatureValid) {
                data.setDataString(objectDataString);
                data.setDataSerialized(true);
            } else {
                // Do NOT echo the attacker-supplied payload into the log -- only the lengths, so
                // operators can correlate attempts without giving payload-hiding for free.
                LOGGER.warn("Rejected unsigned or tampered resource-state payload for resource '"
                    + requestPath + "' (doLen=" + objectDataString.length()
                    + ", sigLen=" + (providedSignature == null ? -1 : providedSignature.length()) + ").");
                // Leave dataString null -- getData() will return null and the resource handler
                // will fall through to its normal not-found path.
            }
        } else {
            data.setDataString(params.get(DATA_BYTES_ARRAY_PARAM));
        }
        return data;
    }
}
