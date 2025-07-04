package org.keycloak.quarkus.runtime.configuration.mappers;

import org.keycloak.config.TruststoreOptions;

import static org.keycloak.quarkus.runtime.configuration.mappers.PropertyMapper.fromOption;

public class TruststorePropertyMappers {

    public static PropertyMapper<?>[] getMappers() {
        return new PropertyMapper[] {
                fromOption(TruststoreOptions.TRUSTSTORE_PATHS)
                        .paramLabel(TruststoreOptions.TRUSTSTORE_PATHS.getKey())
                        .build(),
                fromOption(TruststoreOptions.HOSTNAME_VERIFICATION_POLICY)
                        .paramLabel(TruststoreOptions.HOSTNAME_VERIFICATION_POLICY.getKey())
                        .to("kc.spi-truststore--file--hostname-verification-policy")
                        .build(),
        };
    }

}
