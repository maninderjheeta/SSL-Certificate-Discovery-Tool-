package network.scan.ssl.discovery.utils;

import java.util.ArrayList;
import java.util.List;
import java.util.Observer;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import network.scan.ssl.discovery.model.Report;
import network.scan.ssl.discovery.ui.SSLDiscover;
import network.scan.ssl.discovery.ui.SSLDiscover.IP_VALIDITY_CODE;

import org.apache.log4j.Logger;

/**
 * This class takes the task as input and
 * 
 * @author Maninder Singh Jheeta
 */
public class ThreadManager implements Cloneable {

	private ExecutorService executor = Executors
			.newFixedThreadPool(PropertyHolder.getInstance().getThreadCount());
	private static Logger logger = Logger.getLogger(ThreadManager.class);
	private List<Future<Boolean>> workerList = new ArrayList<>();
	private SSLSearcher sslDiscovery = new SSLSearcher();

	private ThreadManager() {
		logger.info("start ThreadManager");
		Runtime.getRuntime().addShutdownHook(new java.lang.Thread() {
			@Override
			public void run() {
				executor.shutdownNow();
			}
		});
		logger.info("end ThreadManager");
	}

	@Override
	protected Object clone() throws CloneNotSupportedException {
		throw new CloneNotSupportedException("Singleton class");
	}

	public static ThreadManager instance = new ThreadManager();

	/**
	 * Singleton class
	 * 
	 * @return
	 */
	public static synchronized ThreadManager getInstance() {
		logger.info("start getInstance");
		if (instance == null)
			instance = new ThreadManager();
		logger.info("end getInstance");
		return instance;
	}

	/**
	 * Add ip & port scan task
	 * 
	 * @param ov
	 * @param ipAddress
	 * @param portNumberString
	 */
	public void addTask(Observer ov, String ipAddress, String portNumberString) {
		logger.info("start addTask");
		// taskList.add(executor
		// .submit(new Thread(ov, ipAddress, portNumberString)));
		logger.info("end addTask");
	}

	public void reinitializeThreadPool() {
		executor = Executors.newFixedThreadPool(PropertyHolder.getInstance()
				.getThreadCount());
	}

	private class Worker implements Callable<Boolean> {

		// private //logger //logger = //logger.getLogger(Thread.class);
		// Port String
		private final String portNumberString;
		// Ip address
		private final String ipAddress;
		private SSLSearcher sslDiscovery = new SSLSearcher();

		public Worker(String ipAddress, String portNumberString) {
			logger.info("start Thread");
			this.portNumberString = portNumberString;
			this.ipAddress = ipAddress;
			logger.info("end Thread");
		}

		public Boolean call() throws Exception {
			logger.info("start run");
			String[] portNumbers = portNumberString.split("-");

			if (portNumbers.length == 1) {
				logger.debug("port number check - " + portNumbers);
				Report discoverSSL = sslDiscovery.validateSSL(ipAddress.trim(),
						Integer.parseInt(portNumbers[0]));
				if (discoverSSL != null && (discoverSSL.getSslData() != null)) {
					SSLDiscover.getInstance().update(discoverSSL);
				}
			}

			else if (portNumbers.length == 2) {
				int start = Integer.parseInt(portNumbers[0]);
				int end = Integer.parseInt(portNumbers[1]);
				logger.info("IP scan - " + ipAddress + " and port scan - "
						+ start + " to " + start);
				for (; start <= end
						&& !java.lang.Thread.currentThread().isInterrupted(); start++) {
					Report discoverSSL = sslDiscovery.validateSSL(
							ipAddress.trim(), start);
					logger.debug("port scan - " + start);
					logger.debug("data received - " + discoverSSL);
					if (discoverSSL != null && (discoverSSL.getSslData() != null)) {
						logger.info("Data received - "
								+ discoverSSL.getSslData());
						logger.debug("Sending data to GUI Thread");
						SSLDiscover.getInstance().update(discoverSSL);
					}
				}
			}

			logger.info("Thread is sending exit signal");
			logger.info("end run");
			SSLDiscover.getInstance().exitSignal();
			return true;
		}

	}

	public void deligateSingleTask(String ipAddress, String portNumber)
			throws RuntimeException {
		Report report = sslDiscovery.validateSSL(ipAddress,
				Integer.parseInt(portNumber));
		SSLDiscover.getInstance().update(report);
	}

	public int deligateSingleTask(String ipAddress,
			IP_VALIDITY_CODE ipvalidityCode, boolean allPortSearch) {
		return workDivisionOnPort(ipAddress, 1, 65535, 10000);
	}

	public int deligateSingleTask(String ipAddress,
			IP_VALIDITY_CODE ipvalidityCode, String portNumber) {
		String[] portRangeInitial = portNumber.split("-");
		return workDivisionOnPort(ipAddress,
				Integer.parseInt(portRangeInitial[0]),
				Integer.parseInt(portRangeInitial[1]), 1000);
	}

	private int workDivisionOnPort(String ipAddress, int initialRange,
			int endRange, int range) {
		String portRange = " ";
		for (; initialRange <= endRange; initialRange += 1) {

			if ((initialRange + range) > endRange){
				portRange = new StringBuilder().append(initialRange)
						.append("-").append(endRange).toString();
				initialRange =endRange;
			}else
				portRange = new StringBuilder().append(initialRange)
						.append("-").append(initialRange += range).toString();

			Worker worker = new Worker(ipAddress, portRange);
			workerList.add(executor.submit(worker));
		}
		return workerList.size();
	}
}
