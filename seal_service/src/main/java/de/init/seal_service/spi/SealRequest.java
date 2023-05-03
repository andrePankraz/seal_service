/**
 * This file was created by ]init[ AG 2023.
 */
package de.init.seal_service.spi;

import java.util.HashMap;
import java.util.Map;

public class SealRequest {

	public byte[] pdf;

	public Map<String, String> docValues = new HashMap<>();

}