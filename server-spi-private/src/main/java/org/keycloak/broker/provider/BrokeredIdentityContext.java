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
package org.keycloak.broker.provider;

import org.keycloak.models.Constants;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * <p>Represents all identity information obtained from an {@link org.keycloak.broker.provider.IdentityProvider} after a
 * successful authentication.</p>
 *
 * @author Pedro Igor
 */
public class BrokeredIdentityContext {

    private String id;
    private String legacyId;
    private String username;
    private String modelUsername;
    private String email;
    private String firstName;
    private String lastName;
    private String brokerSessionId;
    private String brokerUserId;
    private String token;
    private IdentityProviderModel idpConfig;
    private IdentityProvider idp;
    private Map<String, Object> contextData = new HashMap<>();
    private AuthenticationSessionModel authenticationSession;

    public BrokeredIdentityContext(String id) {
        if (id == null) {
            throw new RuntimeException("No identifier provider for identity.");
        }

        this.id = id;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    /**
     * ID from older API version. For API migrations.
     *
     * @return legacy ID
     */
    public String getLegacyId() {
        return legacyId;
    }

    public void setLegacyId(String legacyId) {
        this.legacyId = legacyId;
    }

    /**
     * Username in remote idp
     *
     * @return
     */
    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    /**
     * username to store in UserModel
     *
     * @return
     */
    public String getModelUsername() {
        return modelUsername;
    }

    public void setModelUsername(String modelUsername) {
        this.modelUsername = modelUsername;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getBrokerSessionId() {
        return brokerSessionId;
    }

    public void setBrokerSessionId(String brokerSessionId) {
        this.brokerSessionId = brokerSessionId;
    }

    public String getBrokerUserId() {
        return brokerUserId;
    }

    public void setBrokerUserId(String brokerUserId) {
        this.brokerUserId = brokerUserId;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public IdentityProviderModel getIdpConfig() {
        return idpConfig;
    }

    public void setIdpConfig(IdentityProviderModel idpConfig) {
        this.idpConfig = idpConfig;
    }

    public IdentityProvider getIdp() {
        return idp;
    }

    public void setIdp(IdentityProvider idp) {
        this.idp = idp;
    }

    public Map<String, Object> getContextData() {
        return contextData;
    }

    public void setContextData(Map<String, Object> contextData) {
        this.contextData = contextData;
    }

    // Set the attribute, which will be available on "Update profile" page and in authenticators
    public void setUserAttribute(String attributeName, String attributeValue) {
        List<String> list = new ArrayList<>();
        list.add(attributeValue);
        getContextData().put(Constants.USER_ATTRIBUTES_PREFIX + attributeName, list);
    }

    // Remove an attribute attribute, which would otherwise be available on "Update profile" page and in authenticators
    public void removeUserAttribute(String attributeName) {
        getContextData().remove(Constants.USER_ATTRIBUTES_PREFIX + attributeName);
    }

    public void setUserAttribute(String attributeName, List<String> attributeValues) {
        getContextData().put(Constants.USER_ATTRIBUTES_PREFIX + attributeName, attributeValues);
    }

    public String getUserAttribute(String attributeName) {
        List<String> userAttribute = (List<String>) getContextData().get(Constants.USER_ATTRIBUTES_PREFIX + attributeName);
        if (userAttribute == null || userAttribute.isEmpty()) {
            return null;
        } else {
            return userAttribute.get(0);
        }
    }

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    public AuthenticationSessionModel getAuthenticationSession() {
        return authenticationSession;
    }

    public void setAuthenticationSession(AuthenticationSessionModel authenticationSession) {
        this.authenticationSession = authenticationSession;
    }

    /**
     * Obtains the set of roles that were granted by mappers.
     *
     * @return a {@link Set} containing the roles.
     */
    private Set<String> getMapperGrantedRoles() {
        Set<String> roles = (Set<String>) this.contextData.get(Constants.MAPPER_GRANTED_ROLES);
        if (roles == null) {
            roles = new HashSet<>();
            this.contextData.put(Constants.MAPPER_GRANTED_ROLES, roles);
        }
        return roles;
    }

    /**
     * Verifies if a mapper has already granted the specified role.
     *
     * @param roleName the name of the role.
     * @return {@code true} if a mapper has already granted the role; {@code false} otherwise.
     */
    public boolean hasMapperGrantedRole(final String roleName) {
        return this.getMapperGrantedRoles().contains(roleName);
    }

    /**
     * Adds the specified role to the set of roles granted by mappers.
     *
     * @param roleName the name of the role.
     */
    public void addMapperGrantedRole(final String roleName) {
        this.getMapperGrantedRoles().add(roleName);
    }

    /**
     * @deprecated use {@link #setFirstName(String)} and {@link #setLastName(String)} instead
     * @param name
     */
    @Deprecated
    public void setName(String name) {
        if (name != null) {
            int i = name.lastIndexOf(' ');
            if (i != -1) {
                firstName  = name.substring(0, i);
                lastName = name.substring(i + 1);
            } else {
                firstName = name;
            }
        }
    }


    @Override
    public String toString() {
        return "{" +
                "id='" + id + '\'' +
                ", username='" + username + '\'' +
                ", email='" + email + '\'' +
                '}';
    }
}
