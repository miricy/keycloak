/*
 * Copyright 2020 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.transaction;

import javax.enterprise.inject.spi.CDI;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSessionFactory;

import javax.transaction.TransactionManager;

public class QuarkusJtaTransactionManagerLookup implements JtaTransactionManagerLookup {

    private static final Logger logger = Logger.getLogger(QuarkusJtaTransactionManagerLookup.class);

    private TransactionManager tm;

    @Override
    public TransactionManager getTransactionManager() {
        return tm;
    }

    @Override
    public void init(Config.Scope config) {
        tm = CDI.current().select(TransactionManager.class).get();
        logger.tracev("TransactionManager = {0}", tm);
        if (tm == null) {
            logger.debug("Could not locate TransactionManager");
        }
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public String getId() {
        return "quarkus";
    }
}
