/**
 * This file was created by ]init[ AG 2023.
 */
package de.init.seal_service.visual;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.time.LocalDate;
import java.util.Base64;
import java.util.Map;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import de.init.seal_service.visual.profile.EntryType;
import de.init.seal_service.visual.profile.Profile;

/**
 * This class encodes JSON data with a matching XML profile into a combined seal
 * string. It follows the standard <a href=
 * "https://www.bsi.bund.de/DE/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/Technische-Richtlinien/TR-nach-Thema-sortiert/tr03171/TR-03171_node.html">BSI
 * TR-03171</a>.
 */
@ApplicationScoped
public class SealEncoder {

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	@ConfigProperty(name = "keystore.visual.private.file")
	String visualPrivateFile;

	@ConfigProperty(name = "keystore.visual.private.pass")
	String visualPrivatePass;

	@ConfigProperty(name = "keystore.visual.private.alias")
	String visualPrivateAlias;

	@ConfigProperty(name = "seal.visual.profile")
	String docProfileNr;

	@ConfigProperty(name = "seal.visual.name")
	String sealerName;

	private PrivateKey privateKey;

	public String encode(final Map<String, String> json) {
		final var profileFile = SealEncoder.class.getResource("/profiles/" + this.docProfileNr + ".xml");
		Profile profile;
		try {
			final var jaxbContext = JAXBContext.newInstance(Profile.class);
			final var jaxbUnmarshaller = jaxbContext.createUnmarshaller();
			profile = (Profile) jaxbUnmarshaller.unmarshal(profileFile);
		} catch (final JAXBException e) {
			throw new RuntimeException("Cannot read profile '" + this.docProfileNr + "'!", e);
		}

		final var encodingStream = new SealEncodingStream();

		// ##########
		// # Header #
		// ##########
		encodingStream.encodeByte((char) 0xDC); // Magic Constant
		encodingStream.encodeByte((char) 0x03); // Version
		encodingStream.encodeC40("D<<"); // Issuing Country

		// Cert Reference ==> {Nr of following Chars in two digits}{Cert Serial Number}
		// ==> Example: 03001
		final var certRef = String.format("%02d", this.visualPrivateAlias.length()) + this.visualPrivateAlias;
		encodingStream.encodeC40(this.sealerName + certRef); // Combined:
		// Signer Identifier == Cert Subject Distinguished Name (CN)
		// Cert Reference == Cert Serial Number
		encodingStream.encodeDate(LocalDate.now()); // Document Issue Date
		encodingStream.encodeDate(LocalDate.now()); // Signature Creation Date
		encodingStream.encodeByte((char) 0x01); // Document Feature Definition Reference
		encodingStream.encodeByte((char) 200); // Document Type Category

		// ################
		// # Message Zone #
		// ################
		encodingStream.encodeMessageC40((char) 0x00, this.docProfileNr);

		for (final EntryType entryType : profile.getEntry()) {
			final var name = entryType.getName();
			var value = json.get(name);
			if (value == null) {
				value = entryType.getDefaultValue();
				if (value == null) {
					if (!entryType.isOptional()) {
						throw new RuntimeException("Cannot read profile value '" + name + "'!");
					}
					continue; // no value, no default and is optional? skip
				}
			}
			final var length = entryType.getLength();
			if (length != null && value.length() > length.intValue()) {
				value = value.substring(length.intValue() - 1) + '…';
			}
			final var tag = (char) entryType.getTag();
			final var type = entryType.getType();
			switch (type) {
			case ALPHANUM:
				encodingStream.encodeMessageC40(tag, value);
				break;
			case STRING:
				encodingStream.encodeMessageString(tag, value);
				break;
			case MULTISTRING:
				encodingStream.encodeMessageString(tag, value);
				break;
			case BINARY:
				encodingStream.encodeMessageBytes(tag, Base64.getDecoder().decode(value));
				break;
			case DATE:
				encodingStream.encodeMessageDate(tag, LocalDate.parse(value));
				break;
			default:
				throw new RuntimeException("Cannot read profile type '" + type + "'!");
			}
		}

		// ##################
		// # Signature Zone #
		// ##################
		// ECDSA 256 Bit: Plain (r,s)-Encoding with 64 Bytes (2 * 256 Bit),
		// no ASN.1/DER encoding with 70 Byte!
		final var signature = sign(encodingStream.toString().getBytes(StandardCharsets.ISO_8859_1));
		encodingStream.encodeMessageSignature(signature);

		return encodingStream.toString();
	}

	@PostConstruct
	void postConstruct() throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException,
			UnrecoverableKeyException {
		final var keystore = KeyStore.getInstance("PKCS12");
		final var pin = this.visualPrivatePass.toCharArray();
		try (var is = SealEncoder.class.getResourceAsStream(this.visualPrivateFile)) {
			if (is == null) {
				throw new RuntimeException("Couldn't find keystore for visual private: " + this.visualPrivateFile);
			}
			keystore.load(is, pin);
		}
		this.privateKey = (PrivateKey) keystore.getKey(this.visualPrivateAlias, pin);
	}

	public byte[] sign(final byte[] data) {
		try {
			final var ecdsaSign = Signature.getInstance("SHA256WITHPLAIN-ECDSA", "BC");
			ecdsaSign.initSign(this.privateKey, new SecureRandom());
			ecdsaSign.update(data);
			return ecdsaSign.sign();
		} catch (final Exception e) {
			throw new RuntimeException("Couldn't sign message!", e);
		}
	}

}