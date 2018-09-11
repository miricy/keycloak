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

package org.keycloak.social.qq;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.util.JSONPObject;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class QQIdentityProvider extends AbstractOAuth2IdentityProvider implements SocialIdentityProvider {

	public static final String AUTH_URL = "https://graph.qq.com/oauth2.0/authorize";
	public static final String TOKEN_URL = "https://graph.qq.com/oauth2.0/token";
	public static final String PROFILE_URL = "https://graph.qq.com/user/get_user_info";
	public static final String DEFAULT_SCOPE = "get_user_info";
        public static final String OPENID_URL="https://graph.qq.com/oauth2.0/me";

	public QQIdentityProvider(KeycloakSession session, OAuth2IdentityProviderConfig config) {
		super(session, config);
		config.setAuthorizationUrl(AUTH_URL);
		config.setTokenUrl(TOKEN_URL);
		config.setUserInfoUrl(PROFILE_URL);
	}

	@Override
	protected boolean supportsExternalExchange() {
		return true;
	}

	@Override
	protected String getProfileEndpointForValidation(EventBuilder event) {
		return PROFILE_URL;
	}


	@Override
	protected BrokeredIdentityContext doGetFederatedIdentity(String accessToken) {
		try {
                        String qqcallback = SimpleHttp.doGet(OPENID_URL+"?access_token="+accessToken, session)
                        		.header("Authorization", "Bearer " + accessToken).asString();
                        String json = qqcallback.substring(qqcallback.indexOf("{"), qqcallback.indexOf("}")+1);
                        ObjectMapper mapper = new ObjectMapper();
            			Map<String, Object> map = new HashMap<String, Object>();
            			// convert JSON string to Map
            			map = mapper.readValue(json, new TypeReference<Map<String, String>>(){});
            			String openid = map.get("openid").toString();
			JsonNode profile = SimpleHttp.doGet(PROFILE_URL+"?access_token="+accessToken+"&oauth_consumer_key="+getConfig().getClientId()+"&openid="+openid, session).header("Authorization", "Bearer " + accessToken).asJson();
                        BrokeredIdentityContext user = new BrokeredIdentityContext(openid);
			user.setUsername(openid);
		        user.setName(getJsonProperty(profile, "nickname"));
		        user.setIdpConfig(getConfig());
		        user.setIdp(this);

			return user;
		} catch (Exception e) {
			throw new IdentityBrokerException("Could not obtain user profile from qq.", e);
		}
	}

	@Override
	protected String getDefaultScopes() {
		return DEFAULT_SCOPE;
	}
}
