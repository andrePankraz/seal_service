package de.init.seal_service.pdf.pdfbox_signature;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import org.junit.jupiter.api.Test;

import io.quarkus.test.junit.QuarkusTest;

/**
 * This class tests the original PDFBox example class
 * {@link CreateVisibleSignature2} with as little as possible changes.
 */
@QuarkusTest
public class CreateVisibleSignature2Test {

	@Test
	public void testMain() throws KeyStoreException, FileNotFoundException, IOException, NoSuchAlgorithmException,
			CertificateException, UnrecoverableKeyException {
		CreateVisibleSignature2.main(new String[] { "src/main/resources/keystore_pdf/zab_pdf_private.p12", "123456",
				"src/test/resources/pdf/Zeugnisbewertung_Musterbescheinigung.pdf",
				"src/test/resources/pdf/Zeugnisbewertung_Datamatrix.png" });
	}

}
