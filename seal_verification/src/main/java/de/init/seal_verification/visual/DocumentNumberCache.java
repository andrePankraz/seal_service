/**
 * This file was created by ]init[ AG 2023.
 */
package de.init.seal_verification.visual;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashSet;
import java.util.Set;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;

/**
 * Sealed documents have a document number. They could be withdrawn
 * (invalidated). Check extewrnal file {@code invalid_document_numbers.txt} for
 * entries (line-separated document numbers).
 */
@ApplicationScoped
public class DocumentNumberCache {

	private Set<String> invalidDocumentNumbers;

	public boolean isDocumentNumberInvalid(String documentNumber) {
		return this.invalidDocumentNumbers.contains(documentNumber);
	}

	@PostConstruct
	void postConstruct() {
		this.invalidDocumentNumbers = new HashSet<>();

		try (var inputStream = getClass().getResourceAsStream("/invalid_document_numbers.txt");
				var reader = new BufferedReader(new InputStreamReader(inputStream))) {
			String line;
			while ((line = reader.readLine()) != null) {
				this.invalidDocumentNumbers.add(line.trim());
			}
		} catch (final IOException e) {
			throw new RuntimeException("Error loading invalid document numbers", e);
		}
	}

}