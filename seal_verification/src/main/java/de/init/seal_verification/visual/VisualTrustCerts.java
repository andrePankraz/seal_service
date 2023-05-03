/**
 * This file was created by ]init[ AG 2023.
 */
package de.init.seal_verification.visual;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Map;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

@ApplicationScoped
public class VisualTrustCerts {

	private static final Logger LOGGER = Logger.getLogger(VisualTrustCerts.class);

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	@ConfigProperty(name = "keystore.visual.public.file")
	String visualPublicFile;

	@ConfigProperty(name = "keystore.visual.public.pass")
	String visualPublicPass;

	private Map<String, PublicKey> publicKeys;

	public PublicKey getPublicKey(final String certAlias) {
		return this.publicKeys.get(certAlias);
	}

	private Map<String, PublicKey> importPublicKeys() {
		KeyStore keystore;
		try {
			keystore = KeyStore.getInstance("PKCS12");
		} catch (final KeyStoreException e) {
			throw new RuntimeException(e);
		}
		final var pin = this.visualPublicPass.toCharArray();
		try (var is = getClass().getResourceAsStream(this.visualPublicFile)) {
			if (is == null) {
				throw new RuntimeException("Couldn't find keystore for visual public: " + this.visualPublicFile);
			}
			keystore.load(is, pin);
		} catch (IOException | NoSuchAlgorithmException | CertificateException e) {
			throw new RuntimeException(e);
		}
		final Map<String, PublicKey> publicKeys = new HashMap<>();
		try {
			LOGGER.info("Loading KeyStore for visual public signatures:");
			final var aliases = keystore.aliases();
			while (aliases.hasMoreElements()) {
				final var alias = aliases.nextElement();
				if (!keystore.isCertificateEntry(alias)) {
					continue;
				}
				LOGGER.info("--- Loading Key: " + alias + " ---\n" + keystore.getCertificate(alias).getPublicKey());
				publicKeys.put(alias, keystore.getCertificate(alias).getPublicKey());
			}
		} catch (final KeyStoreException e) {
			throw new RuntimeException(e);
		}
		return publicKeys;
	}

	@PostConstruct
	void postConstruct() {
		this.publicKeys = importPublicKeys();
	}

}