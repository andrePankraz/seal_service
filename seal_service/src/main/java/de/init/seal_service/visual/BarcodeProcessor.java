/**
 * This file was created by ]init[ AG 2023.
 */
package de.init.seal_service.visual;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.EnumMap;
import java.util.Map;

import javax.enterprise.context.ApplicationScoped;
import javax.imageio.ImageIO;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.BinaryBitmap;
import com.google.zxing.ChecksumException;
import com.google.zxing.DecodeHintType;
import com.google.zxing.FormatException;
import com.google.zxing.LuminanceSource;
import com.google.zxing.NotFoundException;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.BufferedImageLuminanceSource;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.HybridBinarizer;
import com.google.zxing.datamatrix.DataMatrixReader;
import com.google.zxing.datamatrix.DataMatrixWriter;
import com.google.zxing.qrcode.QRCodeReader;
import com.google.zxing.qrcode.QRCodeWriter;

/**
 * This class encodes and decodes barcodes (DataMatrix, QRCode).
 */
@ApplicationScoped
public class BarcodeProcessor {

	static {
		// Prevent I/O operations for ImageIO.write() with ByteArrayOutputStream
		ImageIO.setUseCache(false);
	}

	/**
	 * Decode DataMatrix image.
	 *
	 * @param dataMatrix DataMatrix image
	 * @return contained text
	 */
	public String decodeDataMatrix(final byte[] dataMatrix) {
		try {
			final LuminanceSource source = new BufferedImageLuminanceSource(
					ImageIO.read(new ByteArrayInputStream(dataMatrix)));
			final var bitmap = new BinaryBitmap(new HybridBinarizer(source));
			final var dmr = new DataMatrixReader();
			final Map<DecodeHintType, Object> hints = new EnumMap<>(DecodeHintType.class);
			hints.put(DecodeHintType.PURE_BARCODE, Boolean.TRUE);
			final var r = dmr.decode(bitmap, hints);
			return r.getText();
		} catch (IOException | NotFoundException | ChecksumException | FormatException e) {
			throw new RuntimeException("Couldn't decode DataMatrix!", e);
		}
	}

	/**
	 * Decode QRCode image.
	 *
	 * @param qrCode QRCode image
	 * @return contained text
	 */
	public String decodeQRCode(final byte[] qrCode) {
		try {
			final LuminanceSource source = new BufferedImageLuminanceSource(
					ImageIO.read(new ByteArrayInputStream(qrCode)));
			final var bitmap = new BinaryBitmap(new HybridBinarizer(source));
			final var dmr = new QRCodeReader();
			final Map<DecodeHintType, Object> hints = new EnumMap<>(DecodeHintType.class);
			hints.put(DecodeHintType.PURE_BARCODE, Boolean.TRUE);
			final var r = dmr.decode(bitmap, hints);
			return r.getText();
		} catch (IOException | NotFoundException | ChecksumException | FormatException e) {
			throw new RuntimeException("Couldn't decode DataMatrix!", e);
		}
	}

	/**
	 * Create DataMatrix image.
	 *
	 * @param text   text
	 * @param format image format (png / jpeg)
	 * @param width  image width
	 * @param height image height
	 * @return DataMatrix image
	 */
	public byte[] encodeDataMatrix(final String text, final String format, final int width, final int height) {
		try {
			final var dmw = new DataMatrixWriter();
			final var matrix = dmw.encode(text, BarcodeFormat.DATA_MATRIX, width, height);
			final var bos = new ByteArrayOutputStream();
			MatrixToImageWriter.writeToStream(matrix, format, bos);
			return bos.toByteArray();
		} catch (final IOException e) {
			throw new RuntimeException("Couldn't encode DataMatrix!", e);
		}
	}

	/**
	 * Create QRCode image.
	 *
	 * @param text   text
	 * @param format image format (png / jpeg)
	 * @param width  image width
	 * @param height image height
	 * @return QRCode image
	 */
	public byte[] encodeQRCode(final String text, final String format, final int width, final int height) {
		try {
			final var dmw = new QRCodeWriter();
			final var matrix = dmw.encode(text, BarcodeFormat.QR_CODE, width, height);
			final var bos = new ByteArrayOutputStream();
			MatrixToImageWriter.writeToStream(matrix, format, bos);
			return bos.toByteArray();
		} catch (final IOException | WriterException e) {
			throw new RuntimeException("Couldn't encode QRCode!", e);
		}
	}

}
