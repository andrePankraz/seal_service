package de.init.seal_service.visual;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Map;

import javax.inject.Inject;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.quarkus.test.junit.QuarkusTest;

@QuarkusTest
public class BarcodeProcessorTest {

	@Inject
	BarcodeProcessor barcodeProcessor;

	@Inject
	SealEncoder sealEncoder;

	@Test
	public void testEncodeDataMatrix() {
		final var inputText = "Test";

		final var dataMatrix = this.barcodeProcessor.encodeDataMatrix(inputText, "png", 200, 200);
		Assertions.assertEquals(188, dataMatrix.length);

		final var outputText = this.barcodeProcessor.decodeDataMatrix(dataMatrix);
		Assertions.assertEquals(inputText, outputText);
	}

	@Test
	public void testEncodeQRCode() {
		final var inputText = "Test";

		final var qrCode = this.barcodeProcessor.encodeQRCode(inputText, "png", 200, 200);
		Assertions.assertEquals(279, qrCode.length);

		final var outputText = this.barcodeProcessor.decodeQRCode(qrCode);
		Assertions.assertEquals(inputText, outputText);
	}

	@Test
	public void testWriteDataMatrixTest() throws FileNotFoundException, IOException {
		final Map<String, String> docValues;
		final var docProfileNr = "ZAB001";
		try (var jsonIs = SealEncoderTest.class.getResourceAsStream("/profiles_msgs/" + docProfileNr + ".json")) {
			docValues = new ObjectMapper().readValue(jsonIs, Map.class);
		}

		final var seal = this.sealEncoder.encode(docValues);

		final var dataMatrix = this.barcodeProcessor.encodeDataMatrix(seal, "png", 200, 200);

		final var outputText = this.barcodeProcessor.decodeDataMatrix(dataMatrix);
		Assertions.assertEquals(seal, outputText);

		try (var pdfOs = new FileOutputStream("target/Zeugnisbewertung_Datamatrix.png")) {
			pdfOs.write(dataMatrix);
		}
	}

}