/*
 * Copyright 2021 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.testsuite.webauthn.passwordless;

import org.junit.Before;
import org.keycloak.testsuite.util.BrowserDriverUtil;
import org.keycloak.testsuite.webauthn.AbstractWebAuthnVirtualTest;
import org.keycloak.testsuite.webauthn.AppInitiatedActionWebAuthnTest;
import org.keycloak.testsuite.webauthn.authenticators.DefaultVirtualAuthOptions;

/**
 * @author <a href="mailto:mabartos@redhat.com">Martin Bartos</a>
 */
public class AppInitiatedActionPwdLessTest extends AppInitiatedActionWebAuthnTest {

    @Before
    @Override
    public void setUpVirtualAuthenticator() {
        if (!BrowserDriverUtil.isDriverFirefox(driver)) {
            virtualManager = AbstractWebAuthnVirtualTest.createDefaultVirtualManager(driver, DefaultVirtualAuthOptions.DEFAULT_RESIDENT_KEY.getOptions());
        }
    }

    @Override
    protected boolean isPasswordless() {
        return true;
    }
}
