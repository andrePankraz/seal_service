package de.init.seal_service.visual;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import javax.inject.Inject;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.core.exc.StreamReadException;
import com.fasterxml.jackson.databind.DatabindException;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.quarkus.test.junit.QuarkusTest;

@QuarkusTest
public class SealEncoderTest {

	@Inject
	SealEncoder sealEncoder;

	@Test
	public void testEncode() throws StreamReadException, DatabindException, IOException {
		final Map<String, String> docValues;
		final var docProfileNr = "ZAB001";
		try (var jsonIs = SealEncoderTest.class.getResourceAsStream("/profiles_msgs/" + docProfileNr + ".json")) {
			docValues = new ObjectMapper().readValue(jsonIs, Map.class);
		}

		final var seal = this.sealEncoder.encode(docValues);

		final var len = seal.getBytes(StandardCharsets.ISO_8859_1).length;
		Assertions.assertEquals(229, len);
	}

}