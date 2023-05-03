/**
 * This file was created by ]init[ AG 2023.
 */
package de.init.seal_service.pdf;

import java.awt.geom.Rectangle2D;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Map;
import java.util.regex.Pattern;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

import org.eclipse.microprofile.config.inject.ConfigProperty;

import de.init.seal_service.visual.BarcodeProcessor;
import de.init.seal_service.visual.SealEncoder;

/**
 * This class seals a PDF, visually (DataMatrix) and in PDF metadata (PAdES).
 */
@ApplicationScoped
public class PdfSealer {

	private static final Pattern ATTRIBUTE_PATTERN = Pattern.compile("#\\{(.+?)\\}");

	private static String replaceAttributes(final String input, final Map<String, String> attributeMap) {
		final var matcher = ATTRIBUTE_PATTERN.matcher(input);
		final var result = new StringBuffer();

		while (matcher.find()) {
			final var attributeName = matcher.group(1);
			final var attributeValue = attributeMap.getOrDefault(attributeName, "");
			matcher.appendReplacement(result, attributeValue);
		}

		matcher.appendTail(result);
		return result.toString();
	}

	@Inject
	BarcodeProcessor barcodeProcessor;

	private CreateVisibleSignatureMy createVisibleSignature;

	@ConfigProperty(name = "keystore.pdf.private.file")
	String pdfPrivateFile;

	@ConfigProperty(name = "keystore.pdf.private.pass")
	String pdfPrivatePass;

	@ConfigProperty(name = "keystore.pdf.private.alias")
	String pdfPrivateAlias;

	@ConfigProperty(name = "seal.pdf.name")
	String sealName;

	@ConfigProperty(name = "seal.pdf.location")
	String sealLocation;

	@ConfigProperty(name = "seal.pdf.reason")
	String sealReason;

	@ConfigProperty(name = "seal.pdf.contact")
	String sealContact;

	@Inject
	SealEncoder sealEncoder;

	@PostConstruct
	void postConstruct() throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException,
			UnrecoverableKeyException {
		final var keystore = KeyStore.getInstance("PKCS12");
		final var pin = this.pdfPrivatePass.toCharArray();
		try (var is = getClass().getResourceAsStream(this.pdfPrivateFile)) {
			if (is == null) {
				throw new RuntimeException("Couldn't find keystore for PDF private: " + this.pdfPrivateFile);
			}
			keystore.load(is, pin);
		}
		keystore.getKey(this.pdfPrivateAlias, pin);
		this.createVisibleSignature = new CreateVisibleSignatureMy(keystore, pin);
	}

	public byte[] sealPdf(final byte[] pdf, final Map<String, String> docValues) throws IOException {
		final var seal = this.sealEncoder.encode(docValues);
		// TODO Following callout is just for test. It's not configurable and very
		// ZAB-specific. Better do it before as part of the Input PDF.
		final var pdfExpl = PdfAddValidationExplanation.addExplanation(pdf);
		final var dataMatrixSeal = this.barcodeProcessor.encodeDataMatrix(seal, "png", 200, 200);
		final var rect = new Rectangle2D.Float(70, 580, 200, 220);
		return this.createVisibleSignature.signPDF(pdfExpl, rect, null, "Siegel", dataMatrixSeal, this.sealName,
				this.sealLocation, replaceAttributes(this.sealReason, docValues), this.sealContact);
	}

}