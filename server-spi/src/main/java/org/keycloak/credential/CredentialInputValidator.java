/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
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
package org.keycloak.credential;

import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.util.List;

/**
 * Implentations of this interface can validate CredentialInput, i.e. verify a password.
 * UserStorageProviders and CredentialProviders can implement this interface.
 *
 *
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public interface CredentialInputValidator {
    boolean supportsCredentialType(String credentialType);
    boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType);

    /**
     * Tests whether a credential is valid
     * @param realm The realm in which to which the credential belongs to
     * @param user The user for which to test the credential
     * @param credentialInput the credential details to verify
     * @return true if the passed secret is correct
     */
    boolean isValid(RealmModel realm, UserModel user, CredentialInput credentialInput);
}
