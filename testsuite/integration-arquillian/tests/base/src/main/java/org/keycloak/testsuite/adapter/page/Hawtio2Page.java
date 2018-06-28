package org.keycloak.testsuite.adapter.page;

import org.keycloak.testsuite.page.AbstractPage;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.FindBy;

import javax.ws.rs.core.UriBuilder;
import org.keycloak.testsuite.util.JavascriptBrowser;

import static org.keycloak.testsuite.util.WaitUtils.waitUntilElement;

/**
 * @author mhajas
 */
public class Hawtio2Page extends AbstractPage {

    public String getUrl() {
        if (Boolean.parseBoolean(System.getProperty("app.server.ssl.required"))) {
            return "https://localhost:" + System.getProperty("app.server.https.port", "8543") + "/hawtio";
        }
        return "http://localhost:" + System.getProperty("app.server.http.port", "8180") + "/hawtio";
    }

    @Override
    public UriBuilder createUriBuilder() {
        return UriBuilder.fromUri(getUrl());
    }

    @FindBy(xpath = "//a[@id ='userDropdownMenu']")
    @JavascriptBrowser
    private WebElement dropDownMenu;

    @FindBy(xpath = "//a[@ng-click='userDetails.logout()']")
    @JavascriptBrowser
    private WebElement logoutButton;

    public void logout() {
        waitUntilElement(dropDownMenu).is().clickable();
        dropDownMenu.click();
        waitUntilElement(logoutButton).is().clickable();
        logoutButton.click();
    }
}
