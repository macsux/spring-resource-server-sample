
package mcsss.example.security.resourceserver;

import io.pivotal.cfenv.boot.sso.SpringSecurityDetector;
import io.pivotal.cfenv.core.CfCredentials;
import io.pivotal.cfenv.core.CfService;
import io.pivotal.cfenv.spring.boot.CfEnvProcessor;
import io.pivotal.cfenv.spring.boot.CfEnvProcessorProperties;
import org.springframework.util.ClassUtils;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;

public class CfSingleSignOnResourceProcessor implements CfEnvProcessor {
    private static final String PIVOTAL_SSO_LABEL = "p-identity";
    private static final String SPRING_SECURITY_CLIENT = "spring.security.oauth2.client";
    private static final String SSO_SERVICE = "ssoServiceUrl";

    @Override
    public boolean accept(CfService service) {
        var shouldAccept = isSpringSecurityPresent() && service.existsByLabelStartsWith(PIVOTAL_SSO_LABEL);
        return shouldAccept;
    }

    boolean isSpringSecurityPresent()
    {
        ClassLoader classLoader = SpringSecurityDetector.class.getClassLoader();
        var usingSpringSecurity = ClassUtils.isPresent("org.springframework.security.core.Authentication", classLoader);
        return usingSpringSecurity;
    }

    @Override
    public void process(CfCredentials cfCredentials, Map<String, Object> properties) {
        String authDomain = cfCredentials.getString("auth_domain");
        String issuer = fromAuthDomain(authDomain);
        properties.put("spring.security.oauth2.resourceserver.jwt.issuer-uri", issuer + "/oauth/token");

    }

    @Override
    public CfEnvProcessorProperties getProperties() {
        return CfEnvProcessorProperties.builder()
                .propertyPrefixes(String.join(",", SSO_SERVICE, SPRING_SECURITY_CLIENT))
                .serviceName("Single Sign On").build();
    }

    String fromAuthDomain(String authUri) {
        URI uri = URI.create(authUri);

        String host = uri.getHost();

        if (host == null) {
            throw new IllegalArgumentException("Unable to parse URI host from VCAP_SERVICES with label: \"" + PIVOTAL_SSO_LABEL + "\" and auth_domain: \"" + authUri + "\"");
        }

        String issuerHost = uri.getHost().replaceFirst("login\\.", "uaa.");

        try {
            return new URI(
                    uri.getScheme(),
                    uri.getUserInfo(),
                    issuerHost,
                    uri.getPort(),
                    uri.getPath(),
                    uri.getQuery(),
                    uri.getFragment()
            ).toString();
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException(e.getMessage(), e);
        }
    }
}