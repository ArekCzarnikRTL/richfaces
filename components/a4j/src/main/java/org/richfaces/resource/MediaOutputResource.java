/**
 * License Agreement.
 *
 * Rich Faces - Natural Ajax for Java Server Faces (JSF)
 *
 * Copyright (C) 2007 Exadel, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1 as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 */
package org.richfaces.resource;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

import javax.el.MethodExpression;
import javax.el.ValueExpression;
import javax.faces.component.StateHolder;
import javax.faces.component.UIComponent;
import javax.faces.component.UIComponentBase;
import javax.faces.context.FacesContext;

import org.richfaces.component.AbstractMediaOutput;
import org.richfaces.log.Logger;
import org.richfaces.log.RichfacesLogger;

import com.google.common.base.Strings;

/**
 * @author Nick Belaevski
 * @since 4.0
 */
@DynamicResource
public class MediaOutputResource extends AbstractUserResource implements StateHolder, CacheableResource {
    private static final Logger LOGGER = RichfacesLogger.RESOURCE.getLogger();

    /**
     * Strict allowlist for the {@code createContent} method-expression reconstructed from a client-supplied
     * resource request (the {@code do=} URL parameter). An attacker who can forge that parameter controls the
     * {@link MethodExpression} instance restored in {@link #restoreState}; if we invoked it blindly we would
     * give them arbitrary EL / remote code execution (see CVE-2013-2165, CVE-2018-14667).
     *
     * Legitimate usage is always a simple method reference of the form {@code #{bean.method}} or
     * {@code #{a.b.c}}. This pattern enforces exactly that -- no literals, no brackets, no parentheses,
     * no operators, no whitespace tricks. Anything else is rejected.
     */
    private static final Pattern SAFE_METHOD_EXPRESSION = Pattern.compile(
        "^#\\{[\\p{Alpha}_$][\\p{Alnum}_$]*(?:\\.[\\p{Alpha}_$][\\p{Alnum}_$]*)*\\}$");

    private String contentType;
    private boolean cacheable;
    private MethodExpression contentProducer;
    private ValueExpression expiresExpression;

    /*
     * TODO: add handling for expressions:
     *
     * 1. State saving 2. Evaluation
     */
    private ValueExpression lastModifiedExpression;
    private ValueExpression timeToLiveExpression;
    private Object userData;
    private String fileName;

    public void encode(FacesContext facesContext) throws IOException {
        // Defense-in-depth: restoreState() already validated the expression, but we re-check here in case
        // a different code path populated contentProducer.
        verifyContentProducer(contentProducer);

        OutputStream outStream = facesContext.getExternalContext().getResponseOutputStream();
        contentProducer.invoke(facesContext.getELContext(), new Object[] { outStream, userData });
    }

    /**
     * Reject any {@link MethodExpression} whose expression string is not a trivial bean method reference.
     * Called from both {@link #restoreState} (fail-closed before any further processing) and
     * {@link #encode} (defense-in-depth in case a different path set the field).
     *
     * @throws IllegalStateException if the expression is null or does not match {@link #SAFE_METHOD_EXPRESSION}.
     */
    // Package-private for unit tests.
    static void verifyContentProducer(MethodExpression expression) {
        if (expression == null) {
            throw new IllegalStateException("MediaOutputResource has no createContent expression.");
        }
        String expr = expression.getExpressionString();
        if (expr == null || !SAFE_METHOD_EXPRESSION.matcher(expr).matches()) {
            // Do NOT include the raw expression in the log or exception message -- avoids log
            // injection and keeps attacker payloads out of server logs.
            LOGGER.warn("Rejected unsafe createContent expression on MediaOutputResource "
                + "(length=" + (expr == null ? -1 : expr.length()) + ").");
            throw new IllegalStateException("MediaOutputResource createContent expression is not a "
                + "simple method reference and was rejected.");
        }
    }

    public boolean isTransient() {
        return false;
    }

    public void setTransient(boolean newTransientValue) {
        throw new UnsupportedOperationException();
    }

    public Object saveState(FacesContext context) {
        Object[] state = new Object[5];

        // parent fields state saving
        state[0] = isCacheable(context) ? Boolean.TRUE : Boolean.FALSE;
        state[1] = getContentType();
        state[2] = UIComponentBase.saveAttachedState(context, userData);
        state[3] = UIComponentBase.saveAttachedState(context, contentProducer);
        state[4] = fileName;

        return state;
    }

    public void restoreState(FacesContext context, Object stateObject) {
        Object[] state = (Object[]) stateObject;

        setCacheable((Boolean) state[0]);
        setContentType((String) state[1]);
        userData = UIComponentBase.restoreAttachedState(context, state[2]);
        contentProducer = (MethodExpression) UIComponentBase.restoreAttachedState(context, state[3]);
        fileName = (String) state[4];

        // The state we just restored came from the client-controlled 'do=' URL parameter. Validate the
        // restored expression immediately so we never hold an exploitable MethodExpression in memory.
        verifyContentProducer(contentProducer);
    }

    // TODO use ResourceComponent or exchange object as argument?
    @PostConstructResource
    public void initialize() {
        AbstractMediaOutput uiMediaOutput = (AbstractMediaOutput) UIComponent.getCurrentComponent(FacesContext
            .getCurrentInstance());
        this.setCacheable(uiMediaOutput.isCacheable());
        this.setContentType(uiMediaOutput.getMimeType());
        this.userData = uiMediaOutput.getValue();
        this.contentProducer = uiMediaOutput.getCreateContent();
        this.lastModifiedExpression = uiMediaOutput.getValueExpression("lastModfied");
        this.expiresExpression = uiMediaOutput.getValueExpression("expires");
        this.timeToLiveExpression = uiMediaOutput.getValueExpression("timeToLive");
        this.fileName = uiMediaOutput.getFileName();
    }

    public boolean isCacheable(FacesContext context) {
        return cacheable;
    }

    public void setCacheable(boolean cacheable) {
        this.cacheable = cacheable;
    }

    public Date getExpires(FacesContext context) {
        return null;
    }

    public int getTimeToLive(FacesContext context) {
        return -1;
    }

    public String getEntityTag(FacesContext context) {
        return null;
    }

    public String getContentType() {
        return contentType;
    }

    public void setContentType(String contentType) {
        this.contentType = contentType;
    }

    @Override
    public Map<String, String> getResponseHeaders() {
        Map<String, String> headers = new HashMap<String, String>(2);

        if (!Strings.isNullOrEmpty(fileName)) {
            headers.put("Content-Disposition", "inline; filename=\"" + fileName + "\"");
        }

        return headers;
    }
}
