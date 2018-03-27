package org.thoughtcrime.securesms.push;


import android.content.Context;
import android.support.annotation.Nullable;

import org.thoughtcrime.securesms.BuildConfig;
import org.thoughtcrime.securesms.util.TextSecurePreferences;
import org.whispersystems.signalservice.api.push.TrustStore;
import org.whispersystems.signalservice.internal.configuration.SignalCdnUrl;
import org.whispersystems.signalservice.internal.configuration.SignalServiceConfiguration;
import org.whispersystems.signalservice.internal.configuration.SignalServiceUrl;

import java.util.HashMap;
import java.util.Map;

import okhttp3.CipherSuite;
import okhttp3.ConnectionSpec;
import okhttp3.TlsVersion;

public class SignalServiceNetworkAccess {

  private static final String TAG = SignalServiceNetworkAccess.class.getName();

//  private static final String COUNTRY_CODE_EGYPT = "+20";
  private static final String COUNTRY_CODE_EGYPT = "+1";
  private static final String COUNTRY_CODE_UAE   = "+971";
  private static final String COUNTRY_CODE_OMAN  = "+968";
  private static final String COUNTRY_CODE_QATAR = "+974";

  private static final String SERVICE_REFLECTOR_HOST = "textsecure-service-reflected.whispersystems.org";

  private static final ConnectionSpec SOUQ_CONNECTION_SPEC = new ConnectionSpec.Builder(ConnectionSpec.MODERN_TLS)
      .tlsVersions(TlsVersion.TLS_1_2)
      .cipherSuites(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                    CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                    CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
                    CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
                    CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
                    CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                    CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
                    CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                    CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
                    CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
                    CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                    CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA)
      .supportsTlsExtensions(true)
      .build();

  private static final ConnectionSpec MEDIA_AMAZON_CONNECTION_SPEC = new ConnectionSpec.Builder(ConnectionSpec.MODERN_TLS)
      .tlsVersions(TlsVersion.TLS_1_2)
      .cipherSuites(CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                    CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                    CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                    CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                    CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                    CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                    CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                    CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
                    CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
                    CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384,
                    CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                    CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
                    CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA)
      .supportsTlsExtensions(true)
      .build();

  private final Map<String, SignalServiceConfiguration> censorshipConfiguration;
  private final String[]                                censoredCountries;
  private final SignalServiceConfiguration              uncensoredConfiguration;

  public SignalServiceNetworkAccess(Context context) {
    final TrustStore       trustStore      = new DomainFrontingTrustStore(context);

    final SignalServiceUrl souqService     = new SignalServiceUrl("https://cms.souqcdn.com", SERVICE_REFLECTOR_HOST, trustStore, SOUQ_CONNECTION_SPEC);
    final SignalServiceUrl yahooService    = new SignalServiceUrl("https://view.yahoo.com", SERVICE_REFLECTOR_HOST, trustStore, MEDIA_AMAZON_CONNECTION_SPEC);

    final SignalCdnUrl     souqServiceCdn  = new SignalCdnUrl("https://cms.souqcdn.com", SERVICE_REFLECTOR_HOST, trustStore, SOUQ_CONNECTION_SPEC);
    final SignalCdnUrl     yahooServiceCdn = new SignalCdnUrl("https://view.yahoo.com", SERVICE_REFLECTOR_HOST, trustStore, MEDIA_AMAZON_CONNECTION_SPEC);

    final SignalServiceConfiguration egyptUaeConfig  = new SignalServiceConfiguration(new SignalServiceUrl[] { souqService },
                                                                                      new SignalCdnUrl[] { souqServiceCdn });
    final SignalServiceConfiguration omanQatarConfig = new SignalServiceConfiguration(new SignalServiceUrl[]{ yahooService },
                                                                                      new SignalCdnUrl[] { yahooServiceCdn });

    this.censorshipConfiguration = new HashMap<String, SignalServiceConfiguration>() {{
      put(COUNTRY_CODE_EGYPT, egyptUaeConfig);
      put(COUNTRY_CODE_UAE, egyptUaeConfig);
      put(COUNTRY_CODE_OMAN, omanQatarConfig);
      put(COUNTRY_CODE_QATAR, omanQatarConfig);
    }};

    this.uncensoredConfiguration = new SignalServiceConfiguration(new SignalServiceUrl[] {new SignalServiceUrl(BuildConfig.SIGNAL_URL, new SignalServiceTrustStore(context))},
                                                                  new SignalCdnUrl[] {new SignalCdnUrl(BuildConfig.SIGNAL_CDN_URL, new SignalServiceTrustStore(context))});

    this.censoredCountries = this.censorshipConfiguration.keySet().toArray(new String[0]);
  }

  public SignalServiceConfiguration getConfiguration(Context context) {
    String localNumber = TextSecurePreferences.getLocalNumber(context);
    return getConfiguration(localNumber);
  }

  public SignalServiceConfiguration getConfiguration(@Nullable String localNumber) {
    if (localNumber == null) return this.uncensoredConfiguration;

    for (String censoredRegion : this.censoredCountries) {
      if (localNumber.startsWith(censoredRegion)) {
        return this.censorshipConfiguration.get(censoredRegion);
      }
    }

    return this.uncensoredConfiguration;
  }

  public boolean isCensored(Context context) {
    return getConfiguration(context) != this.uncensoredConfiguration;
  }

  public boolean isCensored(String number) {
    return getConfiguration(number) != this.uncensoredConfiguration;
  }

}
