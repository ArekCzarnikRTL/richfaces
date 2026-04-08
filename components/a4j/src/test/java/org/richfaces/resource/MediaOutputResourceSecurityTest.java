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

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import javax.el.ELContext;
import javax.el.MethodExpression;
import javax.el.MethodInfo;

import org.junit.Test;

/**
 * Regression test for the createContent-expression allowlist in {@link MediaOutputResource}.
 *
 * Historically, a client-controlled {@link MethodExpression} could be restored from the {@code do=}
 * URL parameter of a resource request and then invoked by {@code encode()} -- the basis of the
 * RichFaces EL-injection RCE chain (CVE-2013-2165, CVE-2018-14667). This test pins the behaviour
 * of {@link MediaOutputResource#verifyContentProducer(MethodExpression)} so future edits cannot
 * accidentally loosen the check.
 */
public class MediaOutputResourceSecurityTest {

    /** Minimal stub that returns a fixed expression string -- enough to exercise the allowlist. */
    private static final class StubMethodExpression extends MethodExpression {
        private static final long serialVersionUID = 1L;
        private final String expr;

        StubMethodExpression(String expr) {
            this.expr = expr;
        }

        @Override
        public String getExpressionString() {
            return expr;
        }

        @Override
        public boolean isLiteralText() {
            return false;
        }

        @Override
        public int hashCode() {
            return expr == null ? 0 : expr.hashCode();
        }

        @Override
        public boolean equals(Object other) {
            return other instanceof StubMethodExpression
                && ((StubMethodExpression) other).expr.equals(expr);
        }

        @Override
        public MethodInfo getMethodInfo(ELContext context) {
            return null;
        }

        @Override
        public Object invoke(ELContext context, Object[] params) {
            throw new AssertionError("invoke() must not be called -- the allowlist should have rejected "
                + "this expression before invocation.");
        }
    }

    // --- accepted: plain method references ---------------------------------------------------

    @Test
    public void acceptsSimpleBeanMethodReference() {
        MediaOutputResource.verifyContentProducer(new StubMethodExpression("#{bean.paint}"));
    }

    @Test
    public void acceptsDottedBeanChain() {
        MediaOutputResource.verifyContentProducer(new StubMethodExpression("#{outer.inner.method}"));
    }

    @Test
    public void acceptsUnderscoreAndDollarIdentifiers() {
        MediaOutputResource.verifyContentProducer(new StubMethodExpression("#{_bean.$method_1}"));
    }

    // --- rejected: known attack shapes --------------------------------------------------------

    @Test
    public void rejectsNullExpression() {
        assertRejected(null);
    }

    @Test
    public void rejectsEmptyString() {
        assertRejected("");
    }

    @Test
    public void rejectsLiteralText() {
        assertRejected("not an expression");
    }

    @Test
    public void rejectsMethodCallWithParens() {
        // The classic CVE-2013-2165 shape: arbitrary method invocation in EL.
        assertRejected("#{''.getClass().forName('java.lang.Runtime').getMethod('exec').invoke(null)}");
    }

    @Test
    public void rejectsParensEvenIfOtherwiseSimple() {
        assertRejected("#{bean.method()}");
    }

    @Test
    public void rejectsBracketAccessor() {
        // Bracket notation can reach dynamic members -- not needed for createContent.
        assertRejected("#{bean['method']}");
    }

    @Test
    public void rejectsStringLiteral() {
        assertRejected("#{'malicious'}");
    }

    @Test
    public void rejectsConcatenation() {
        assertRejected("#{bean.a + bean.b}");
    }

    @Test
    public void rejectsWhitespaceInsideBraces() {
        // Be strict: no whitespace tricks. If a user really needs it they can remove the space.
        assertRejected("#{ bean.paint }");
    }

    @Test
    public void rejectsLeadingText() {
        assertRejected("prefix#{bean.paint}");
    }

    @Test
    public void rejectsTrailingText() {
        assertRejected("#{bean.paint}suffix");
    }

    @Test
    public void rejectsMultipleExpressions() {
        assertRejected("#{bean.a}#{bean.b}");
    }

    @Test
    public void rejectsMissingHashPrefix() {
        assertRejected("{bean.paint}");
    }

    @Test
    public void rejectsDollarPrefix() {
        // createContent is a MethodExpression, not a deferred value expression; reject ${...}.
        assertRejected("${bean.paint}");
    }

    @Test
    public void rejectsIdentifierStartingWithDigit() {
        assertRejected("#{1bean.paint}");
    }

    // ------------------------------------------------------------------------------------------

    private static void assertRejected(String expr) {
        MethodExpression me = expr == null ? null : new StubMethodExpression(expr);
        try {
            MediaOutputResource.verifyContentProducer(me);
            fail("verifyContentProducer should have rejected expression: " + expr);
        } catch (IllegalStateException expected) {
            assertNotNull(expected.getMessage());
        }
    }
}
