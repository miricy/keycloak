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

package org.keycloak.social.wechat;

import com.fasterxml.jackson.databind.JsonNode;
import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.models.KeycloakSession;
import org.jboss.logging.Logger;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class WechatIdentityProvider extends AbstractOAuth2IdentityProvider implements SocialIdentityProvider {

	public static final String AUTH_URL = "https://open.weixin.qq.com/connect/qrconnect";
	public static final String TOKEN_URL = "https://api.weixin.qq.com/sns/oauth2/access_token";
	public static final String PROFILE_URL = "https://api.weixin.qq.com/sns/userinfo";
	public static final String DEFAULT_SCOPE = "snsapi_login";

	public WechatIdentityProvider(KeycloakSession session, OAuth2IdentityProviderConfig config) {
		super(session, config);
		config.setAuthorizationUrl(AUTH_URL);
		config.setTokenUrl(TOKEN_URL);
		config.setUserInfoUrl(PROFILE_URL);
	}

	@Override
	protected BrokeredIdentityContext doGetFederatedIdentity(String accessToken,String openid) {
		try {
			JsonNode profile = SimpleHttp.doGet(PROFILE_URL+"?access_token="+accessToken+"&openid="+openid, session).header("Authorization", "Bearer " + accessToken).asJson();
                        logger.error("token:"+accessToken+"  openid:"+openid + "profile: " + profile);
			BrokeredIdentityContext user = new BrokeredIdentityContext(getJsonProperty(profile, "openid"));

			String username = getJsonProperty(profile, "openid");
			user.setUsername(username);
			user.setName(getJsonProperty(profile, "nickname"));
			//user.setEmail(getJsonProperty(profile, "email"));
			user.setIdpConfig(getConfig());
			user.setIdp(this);

			AbstractJsonUserAttributeMapper.storeUserProfileForMapper(user, profile, getConfig().getAlias());

			return user;
		} catch (Exception e) {
			throw new IdentityBrokerException("Could not obtain user profile from wechat.", e);
		}
	}

	@Override
	protected String getDefaultScopes() {
		return DEFAULT_SCOPE;
	}
}
