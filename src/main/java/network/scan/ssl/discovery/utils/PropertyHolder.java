package network.scan.ssl.discovery.utils;

import java.io.FileInputStream;
import java.util.Properties;
import org.apache.log4j.Logger;

/**
 * Application property 
 *  
 * @author Maninder Singh Jheeta
 */
public class PropertyHolder {

	private Properties props;
	private static Logger logger = Logger
			.getLogger(PropertyHolder.class);

	private PropertyHolder() {
		try {
			props = new Properties();
			props.load(PropertyHolder.class.getClassLoader().getResourceAsStream("application.properties"));

		} catch (Exception e) {
			logger.error(e);
			logger.error("Application quit due to unavilability of resource"
					+ " - \"application.properties\"");
			System.exit(0);
		}
	}

	private static PropertyHolder INSTANCE = new PropertyHolder();

	public static PropertyHolder getInstance() {
		return INSTANCE;
	}

	private int threadCount = 10;

	public String getReportName() {
		String reportName = "SSL Scan Report.xls";
		String rName = props.getProperty("application.report.name");
		if (!rName.trim().isEmpty()) {
			if (rName.contains(".") && rName.endsWith(".xls"))
				reportName = rName;
			else
				reportName = rName.split("\\.")[0] + ".xls";
		}
		return reportName;
	}
	private String filePath = System.getProperty("user.home");
	public String getFilePath() {
		return this.filePath;
	}
	
	public void setDefault(){
		this.filePath = System.getProperty("user.home");
		
	}
	
	public void setFilePath(String filePath){
		this.filePath = filePath;
	}

	public int getThreadCount() {
		int threadCount = 10;
		try {
			this.threadCount = threadCount = Integer.parseInt(props
					.getProperty("application.threadcount"));
		} catch (RuntimeException e) {
			logger.error(e.getLocalizedMessage(), e);
		}
		return threadCount;
	}

	public synchronized boolean setThreadCount(int threadCount) {
		if (threadCount < 0 || threadCount >= 25)
			return false;
		this.threadCount = threadCount;
		return true;
	}

	@Override
	protected Object clone() throws CloneNotSupportedException {
		throw new CloneNotSupportedException("Singleton class");
	}

	public int getHTTPSTimeout() {
		return Integer.parseInt(props.getProperty("application.https.timeout"));
	}
}
