package network.scan.ssl.discovery.model;


/**
 *
 * @author Maninder Singh Jheeta
 */
public class Report {

	/**
	 * SSL information
	 */
	private SSLData sslData;

	/**
	 * List of error ports
	 */
	// private List<Port> errorPort = new ArrayList<Port>();

	public SSLData getSslData() {
		return sslData;
	}

	public void setSslData(SSLData sslData) {
		this.sslData = sslData;
	}

	@Override
	public String toString() {
		return new StringBuilder(super.toString()).append("\nSSL detected - ")
				.append(sslData).toString();
	}
}
