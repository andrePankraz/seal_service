/**
 * This file was created by ]init[ AG 2023.
 */
package de.init.seal_verification.visual;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;

@ApplicationScoped
public class DocumentProfileCache {

	private Map<String, String> docProfiles;

	public String getDocProfile(String docProfileNr) {
		return this.docProfiles.get(docProfileNr);
	}

	@PostConstruct
	void postConstruct() throws URISyntaxException {
		this.docProfiles = new HashMap<>();

		final var profilesPath = Paths.get(getClass().getResource("/profiles").toURI());

		try (var directoryStream = Files.newDirectoryStream(profilesPath, "*.xml")) {
			for (final Path path : directoryStream) {
				final var fileName = path.getFileName().toString();
				final var docProfileNr = fileName.substring(0, fileName.lastIndexOf('.'));

				try (var inputStream = Files.newInputStream(path);
						var reader = new BufferedReader(new InputStreamReader(inputStream))) {
					final var stringBuilder = new StringBuilder();
					String line;
					while ((line = reader.readLine()) != null) {
						stringBuilder.append(line);
					}
					this.docProfiles.put(docProfileNr, stringBuilder.toString());
				} catch (final IOException e) {
					throw new RuntimeException("Error loading XML profile: " + fileName, e);
				}
			}
		} catch (final IOException e) {
			throw new RuntimeException("Error listing XML profiles in /profiles directory", e);
		}
	}

}
