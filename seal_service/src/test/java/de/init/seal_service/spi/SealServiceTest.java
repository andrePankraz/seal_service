package de.init.seal_service.spi;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.is;

import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Map;

import org.apache.pdfbox.io.IOUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.quarkus.test.junit.QuarkusTest;
import io.restassured.http.ContentType;
import io.restassured.mapper.ObjectMapperType;

@QuarkusTest
public class SealServiceTest {

	@Test
	public void testHelloEndpoint() {
		given().when().get("/seal_service/ping").then().statusCode(200).body(is("Hello from RESTEasy Reactive"));
	}

	@Test
	public void testSealPdf() throws IOException {
		final var signatureRequest = new SealRequest();

		try (var pdfIs = SealServiceTest.class.getResourceAsStream("/pdf/Zeugnisbewertung_Musterbescheinigung.pdf")) {
			signatureRequest.pdf = IOUtils.toByteArray(pdfIs);
		}
		final var docProfileNr = "ZAB001";
		try (var jsonIs = SealServiceTest.class.getResourceAsStream("/profiles_msgs/" + docProfileNr + ".json")) {
			signatureRequest.docValues = new ObjectMapper().readValue(jsonIs, Map.class);
		}

		final var sealedPdf = given().contentType(ContentType.JSON).body(signatureRequest, ObjectMapperType.JACKSON_2)
				.when().post("/seal_service/seal").then().statusCode(200)
				.header("Content-Disposition", equalTo("attachment; filename=\"signed_pdf.pdf\""))
				.header("Content-Length", greaterThan("0")).extract().asByteArray();

		try (var pdfOs = new FileOutputStream("target/Zeugnisbewertung_Musterbescheinigung_sealed_remote.pdf")) {
			pdfOs.write(sealedPdf);
		}
		Assertions.assertTrue(sealedPdf.length > signatureRequest.pdf.length);
	}

}