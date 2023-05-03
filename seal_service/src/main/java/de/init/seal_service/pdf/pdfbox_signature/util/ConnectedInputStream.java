/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.init.seal_service.pdf.pdfbox_signature.util;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;

/**
 * Delegate class to close the connection when the class gets closed.
 *
 * @author Tilman Hausherr
 */
public class ConnectedInputStream extends InputStream {
	HttpURLConnection con;
	InputStream is;

	public ConnectedInputStream(final HttpURLConnection con, final InputStream is) {
		this.con = con;
		this.is = is;
	}

	@Override
	public int available() throws IOException {
		return is.available();
	}

	@Override
	public void close() throws IOException {
		is.close();
		con.disconnect();
	}

	@Override
	public synchronized void mark(final int readlimit) {
		is.mark(readlimit);
	}

	@Override
	public boolean markSupported() {
		return is.markSupported();
	}

	@Override
	public int read() throws IOException {
		return is.read();
	}

	@Override
	public int read(final byte[] b) throws IOException {
		return is.read(b);
	}

	@Override
	public int read(final byte[] b, final int off, final int len) throws IOException {
		return is.read(b, off, len);
	}

	@Override
	public synchronized void reset() throws IOException {
		is.reset();
	}

	@Override
	public long skip(final long n) throws IOException {
		return is.skip(n);
	}
}
