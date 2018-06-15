package org.keycloak.testsuite.adapter;

import org.keycloak.testsuite.adapter.servlet.SAMLServletsAdapterTest;
import org.keycloak.testsuite.arquillian.annotation.AppServerContainer;

/**
 * @author mhajas
 */
@AppServerContainer("app-server-remote")
public class RemoteSAMLAdapterTest extends SAMLServletsAdapterTest {

}
