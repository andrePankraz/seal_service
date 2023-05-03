package de.init.seal_verification.spi;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.is;

import org.junit.jupiter.api.Test;

import io.quarkus.test.junit.QuarkusTest;

@QuarkusTest
public class SealVerificationTest {

	@Test
	public void testHelloEndpoint() {
		given().when().get("/seal_verification/ping").then().statusCode(200).body(is("Hello from RESTEasy Reactive"));
	}

}