package network.scan.ssl.discovery.utils;

import java.io.IOException;
import java.net.URL;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.SocketFactory;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;

import network.scan.ssl.discovery.model.Report;
import network.scan.ssl.discovery.model.SSLData;

import org.apache.log4j.Logger;

/**
 *
 * @author Maninder Singh Jheeta
 */
public class SSLSearcher {

	private static Logger logger = Logger.getLogger(SSLSearcher.class);
	public static final int TIMEOUT_HTTPS = PropertyHolder.getInstance()
			.getHTTPSTimeout();

	/**
	 * Discover SSL Certificate & Other open ports
	 * 
	 * @param ip
	 * @param port
	 * @return
	 */
	public Report validateSSL(String ip, int port) {
		logger.info("start discoverSSL");
		Report result = new Report();
		try {
			Certificate[] certificates = getCertificates(ip, port);
			if (certificates != null) {
				for (Certificate cert : certificates) {
					if (cert instanceof X509Certificate) {
						SSLData infoSSL = getSSLDetail((X509Certificate) cert,
								ip, String.valueOf(port));
						result.setSslData(infoSSL);
					}
					break;
				}
			}
		} catch (Exception e) {
			logger.error(e);
			e.printStackTrace();
			//TODO Error port
			System.out.println("HTTPS Port open - " + port);
			System.out.println("Error in SSL communication");
		}
		logger.info("end discoverSSL");
		return result;
	}

	/**
	 * Discover SSL
	 * 
	 * @param ip
	 * @param port
	 * @return
	 * @throws Exception
	 */
	private synchronized Certificate[] getCertificates(String ip, int port)
			throws Exception {
		logger.info("start getSSLDetail");
		HttpsURLConnection conn = null;
		final DefaultTrustManager defaultTrustManager = new DefaultTrustManager();
		try {

			SSLContext ctx = SSLContext.getInstance("TLS");
			ctx.init(new KeyManager[0],
					new TrustManager[] { defaultTrustManager },
					new SecureRandom());
			SSLContext.setDefault(ctx);

			URL url = new URL(
					new StringBuffer("https://" + ip + ":" + port).toString());
			conn = (HttpsURLConnection) url.openConnection();
			conn.setSSLSocketFactory(ctx.getSocketFactory());
			conn.setConnectTimeout(TIMEOUT_HTTPS);
			conn.setHostnameVerifier(new HostnameVerifier() {
				public boolean verify(String arg0, SSLSession arg1) {
					return true;
				}
			});
			conn.connect();
			Certificate[] certs = conn.getServerCertificates();

			logger.info("end getSSLDetail");
			return certs;
		} catch (Exception e) {
			final X509Certificate[] certificates = defaultTrustManager
					.getCerts();
			logger.info("end getSSLDetail");
			// this cover the scanrio of bad certificate
			if (certificates != null) {
				return certificates;
			} else
				throw e;
		} finally {
			try {
				if (conn != null)
					conn.disconnect();
			} catch (Exception e) {
			}

		}
		// return null;
	}

	private SocketFactory factory = SSLSocketFactory.getDefault();

	/**
	 * Scan specific port
	 * 
	 * @param ip
	 * @param port
	 * @return
	 * @throws IOException
	 *//*
	public Port getPortInfo(final String ip, final int port) throws IOException {
		logger.info("start portIsOpen");
		logger.info("ip - " + ip + " and port " + port);
		Port portReturn = new Port();
		SSLSocket sslSocket = null;
		try {

			sslSocket = (SSLSocket) factory.createSocket();
			sslSocket.connect(new InetSocketAddress(ip, port), TIMEOUT_HTTPS);
			logger.info("got open Port " + ip + ":" + port);
		} catch (Exception e) {
			logger.error("HTTP Port open - " + ip + ":" + port, e);
			portReturn.setHostPort(ip + ":" + port);
			portReturn.setIsHttps(false);
			portReturn.setIsHttpsConnected(false);
			portReturn.setErrorMessage(e.getMessage());
			logger.info("end getSSLDetail");
			return portReturn;
		} finally {
			if (sslSocket != null)
				sslSocket.close();
		}
		portReturn.setHostPort(ip + ":" + port);
		portReturn.setIsHttps(true);
		portReturn.setIsHttpsConnected(true);
		logger.info("end getSSLDetail");
		return portReturn;
	}*/

	private SSLData getSSLDetail(X509Certificate xcert, String ipaddres,
			String port) {
		logger.info("start getSSLDetail");
		String[] subject = xcert.getSubjectX500Principal().getName().split(",");
		String friendlyName = "";
		for (String string : subject) {
			if (string.startsWith("CN=")) {
				friendlyName = string.substring(string.indexOf('=') + 1);
				break;
			}
		}
		X500Principal principal = xcert.getIssuerX500Principal();
		String[] names = principal.getName().split(",");
		String issuerName = "";
		for (String string : names) {
			if (string.startsWith("O=")) {
				issuerName = string.substring(string.indexOf('=') + 1);
				break;
			}
		}
		logger.info("Certificate Name - " + friendlyName + " and expiry - "
				+ xcert.getNotAfter());
		SSLData sslInfo = new SSLData();
		sslInfo.setExpiryDate(xcert.getNotAfter());
		sslInfo.setIsser(issuerName);
		sslInfo.setSerialNumber(xcert.getSerialNumber().toString());
		sslInfo.setServerName(new StringBuilder(ipaddres + ":" + port)
				.toString());
		sslInfo.setFriendlyName(friendlyName);
		logger.debug("Certificate detail - " + friendlyName + ","
				+ new StringBuilder(ipaddres + ":" + port).toString() + ","
				+ issuerName + "," + xcert.getSerialNumber().toString());
		logger.info("end getSSLDetail");
		return sslInfo;
	}

	/**
	 * Default Trust Manager to trust all certificate
	 */
	private class DefaultTrustManager implements X509TrustManager {

		private X509Certificate[] certs = null;

		public void checkClientTrusted(X509Certificate[] arg0, String arg1)
				throws CertificateException {
		}

		public void checkServerTrusted(X509Certificate[] certs, String arg1)
				throws CertificateException {
			this.certs = certs;
		}

		public X509Certificate[] getAcceptedIssuers() {
			return null;
		}

		public X509Certificate[] getCerts() {
			return this.certs;
		}
	}
}
