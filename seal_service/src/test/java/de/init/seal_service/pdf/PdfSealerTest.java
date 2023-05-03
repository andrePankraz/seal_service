package de.init.seal_service.pdf;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Map;

import javax.inject.Inject;

import org.apache.pdfbox.io.IOUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.quarkus.test.junit.QuarkusTest;

@QuarkusTest
public class PdfSealerTest {

	@Inject
	PdfSealer pdfSealer;

	@Test
	public void testSealPdf() throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException,
			CertificateException, IOException {
		final byte[] pdf;
		try (var pdfIs = PdfSealerTest.class.getResourceAsStream("/pdf/Zeugnisbewertung_Musterbescheinigung.pdf")) {
			pdf = IOUtils.toByteArray(pdfIs);
		}
		final Map<String, String> docValues;
		final var docProfileNr = "ZAB001";
		try (var jsonIs = PdfSealerTest.class.getResourceAsStream("/profiles_msgs/" + docProfileNr + ".json")) {
			docValues = new ObjectMapper().readValue(jsonIs, Map.class);
		}

		final var sealedPdf = this.pdfSealer.sealPdf(pdf, docValues);

		try (var pdfOs = new FileOutputStream("target/Zeugnisbewertung_Musterbescheinigung_sealed.pdf")) {
			pdfOs.write(sealedPdf);
		}
		Assertions.assertTrue(sealedPdf.length > pdf.length);
	}

}