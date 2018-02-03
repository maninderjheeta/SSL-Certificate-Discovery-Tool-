package network.scan.ssl.discovery.ui;

import java.awt.EventQueue;
import java.awt.Font;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;

import network.scan.ssl.discovery.model.Report;
import network.scan.ssl.discovery.model.SSLData;
import network.scan.ssl.discovery.utils.ThreadManager;

import org.apache.log4j.Logger;

public class SSLDiscover extends JFrame {

	/**
	 * 
	 */
	private static final long serialVersionUID = -8920728744629681369L;
	private JPanel contentPane;
	private JTextField ipField;
	private JLabel lblPort;
	private JTextField portField;
	private JButton searchButton;
	private JTable resultTable;
	private volatile boolean isRunning = false;
	private static final Logger logger = Logger.getLogger(SSLDiscover.class);
	private List<List<Object>> sslList = new ArrayList<List<Object>>();
	private List<List<Object>> errorDataList = new ArrayList<List<Object>>();

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					SSL_DISCOVERY = new SSLDiscover();
					SSL_DISCOVERY.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	private static SSLDiscover SSL_DISCOVERY;
	private int deligateSingleTask;
	private JLabel iconLabel;

	public static SSLDiscover getInstance() {
		return SSL_DISCOVERY;
	}

	/**
	 * Create the frame.
	 */
	private SSLDiscover() {
		setResizable(false);
		setTitle("SSL Network Discovery Tool");
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(100, 100, 746, 359);
		contentPane = new javax.swing.JPanel();
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
		setContentPane(contentPane);
		contentPane.setLayout(null);

		iconLabel = new JLabel();

		JLabel lblIpAddress = new JLabel("IP Address / Url");
		lblIpAddress.setFont(new Font("Times New Roman", Font.BOLD, 12));
		lblIpAddress.setBounds(26, 28, 99, 14);
		contentPane.add(lblIpAddress);

		ipField = new JTextField();
		ipField.setToolTipText("Use comma(,) for multiple");
		ipField.setBounds(126, 25, 273, 20);
		contentPane.add(ipField);
		ipField.setColumns(10);

		lblPort = new javax.swing.JLabel("Port");
		lblPort.setBounds(421, 28, 46, 14);
		contentPane.add(lblPort);

		portField = new javax.swing.JTextField();
		portField.setToolTipText("Use dash(,) for range");
		portField.setBounds(462, 25, 144, 20);
		contentPane.add(portField);
		portField.setColumns(10);

		searchButton = new JButton("Search");
		searchButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				iconLabel.setVisible(true);
				jButton1ActionPerformed(e);
				// iconLabel.setVisible(false);
			}
		});
		searchButton.setBounds(631, 24, 89, 23);
		contentPane.add(searchButton);

		JScrollPane scrollPane = new JScrollPane();
		scrollPane.setBounds(26, 98, 694, 222);
		contentPane.add(scrollPane);

		resultTable = new JTable(2, 5);

		DataTableModel myTableModel = new DataTableModel(new Object[][] {},
				new String[] { "Server Name", "Certificate Name",
						"Expiration Date", "Issuer" });
		resultTable.setModel(myTableModel);
		resultTable.setName("Table");
		resultTable.getTableHeader().setReorderingAllowed(false);
		scrollPane.setViewportView(resultTable);

		ClassLoader cldr = this.getClass().getClassLoader();
		java.net.URL imageURL = cldr.getResource("img/progress.gif");
		ImageIcon imageIcon = new ImageIcon(imageURL);

		iconLabel.setBounds(271, 56, 184, 36);
		iconLabel.setIcon(imageIcon);
		imageIcon.setImageObserver(iconLabel);
		iconLabel.setVisible(false);
		contentPane.add(iconLabel);
	}

	/**
	 * Scanning event performed
	 * 
	 * @param evt
	 */
	private void jButton1ActionPerformed(java.awt.event.ActionEvent evt) {
		boolean allPortSearch = false;
		// PORT number validation
		PORT_VALIDITY_CODE portValidityCode = validatePort();
		if (portValidityCode == PORT_VALIDITY_CODE.INVALID) {
			JOptionPane.showMessageDialog(this, "Invalid port number",
					"Input Error", JOptionPane.ERROR_MESSAGE);
			return;
		} else if (portValidityCode == PORT_VALIDITY_CODE.EMPTY)
			allPortSearch = true;
		IP_VALIDITY_CODE ipvalidityCode = validityIP();
		if (ipvalidityCode == IP_VALIDITY_CODE.INVALID) {
			JOptionPane.showMessageDialog(this, "Invalid IP address",
					"Input Error", JOptionPane.ERROR_MESSAGE);
			return;
		}
		((DataTableModel) resultTable.getModel()).setRowCount(0);
		isRunning = true;
		String ipAddress = ipField.getText();
		String portNumber = portField.getText();
		if (ipvalidityCode == IP_VALIDITY_CODE.SINGLE) {
			assignWorkForIP(ipAddress, ipvalidityCode, portNumber,
					portValidityCode, allPortSearch);
		}
		if (ipvalidityCode == IP_VALIDITY_CODE.COMMA_SEPERATED) {
			String[] ipAddresses = ipAddress.split(",");
			for (String ip : ipAddresses) {
				assignWorkForIP(ip, ipvalidityCode, portNumber,
						portValidityCode, allPortSearch);
			}
		}
	}

	private void assignWorkForIP(String ipAddress,
			IP_VALIDITY_CODE ipvalidityCode, String portNumber,
			PORT_VALIDITY_CODE portValidityCode, boolean allPortSearch) {
		if (portValidityCode == PORT_VALIDITY_CODE.SINGLE) {
			ThreadManager.getInstance().deligateSingleTask(ipAddress,
					portNumber);
			iconLabel.setVisible(false);
		} else if (allPortSearch) {
			deligateSingleTask = ThreadManager.getInstance()
					.deligateSingleTask(ipAddress, ipvalidityCode,
							allPortSearch);
		} else {
			deligateSingleTask = ThreadManager.getInstance()
					.deligateSingleTask(ipAddress, ipvalidityCode, portNumber);
		}
	}

	public static enum IP_VALIDITY_CODE {
		INVALID, SINGLE, COMMA_SEPERATED, DASH_SEPERATED, COMMA_DASH_SEPERATED
	}

	private IP_VALIDITY_CODE validityIP() {
		String ip = ipField.getText();
		if (ip.isEmpty())
			return IP_VALIDITY_CODE.INVALID;
		else if (ip.contains("-")) {
			if (ip.contains(",")) {
				String[] ipRanges = ip.split(",");
				for (String ipRange : ipRanges) {
					if (validateIPRange(ipRange) == IP_VALIDITY_CODE.INVALID)
						return IP_VALIDITY_CODE.INVALID;
				}
				return IP_VALIDITY_CODE.COMMA_DASH_SEPERATED;
			} else {
				return validateIPRange(ip);
			}

		} else if (ip.contains(",")) {
			String[] ips = ip.split(",");
			for (String ipString : ips) {
				if (!ipString.matches(IPADDRESS_PATTERN)) {
					return IP_VALIDITY_CODE.INVALID;
				}
			}
			return IP_VALIDITY_CODE.COMMA_SEPERATED;
		} else if (ip.matches(IPADDRESS_PATTERN)) {
			return IP_VALIDITY_CODE.SINGLE;
		}
		return IP_VALIDITY_CODE.INVALID;
	}

	private IP_VALIDITY_CODE validateIPRange(String ip) {
		String[] bothEnds = ip.split("-");
		if (bothEnds.length == 2) {
			String firstEnd = bothEnds[0];
			String lastEnd = bothEnds[1];
			if (firstEnd.matches(IPADDRESS_PATTERN)) {
				if (!lastEnd.matches(IPADDRESS_PATTERN)) {
					String[] ipFrags = lastEnd.split("\\.");
					try {
						for (String ipFrag : ipFrags) {
							int ipFragNumber = Integer.parseInt(ipFrag);
							if (ipFragNumber > 255)
								return IP_VALIDITY_CODE.INVALID;
						}
					} catch (Exception e) {
						e.printStackTrace();
						return IP_VALIDITY_CODE.INVALID;
					}
				}
			} else {
				return IP_VALIDITY_CODE.INVALID;
			}
		}
		return IP_VALIDITY_CODE.DASH_SEPERATED;
	}

	public static enum PORT_VALIDITY_CODE {
		INVALID, EMPTY, SINGLE, DASH_SEPERATED
	}

	private PORT_VALIDITY_CODE validatePort() {
		String portNumberString = portField.getText();
		if (portNumberString.isEmpty()) {
			return PORT_VALIDITY_CODE.EMPTY;
		} else if (portNumberString.matches("[0-9-]*")) {
			try {
				if (portNumberString.contains("-")) {
					String[] portNumberStrings = portNumberString.split("-");
					if (portNumberStrings.length > 4
							|| portNumberStrings.length < 0)
						return PORT_VALIDITY_CODE.INVALID;
					for (String prtNumber : portNumberStrings) {
						int number = Integer.parseInt(prtNumber);
						if (number > 65535)
							return PORT_VALIDITY_CODE.INVALID;
					}
				} else {
					int number = Integer.parseInt(portNumberString);
					if (number > 65535 || number < 0)
						return PORT_VALIDITY_CODE.INVALID;
					return PORT_VALIDITY_CODE.SINGLE;
				}
			} catch (RuntimeException e) {
				e.printStackTrace();
			}
			return PORT_VALIDITY_CODE.DASH_SEPERATED;
		} else {
			return PORT_VALIDITY_CODE.INVALID;
		}
	}

	public void update(Report sslReport) {
		logger.info("start update");
		final DefaultTableModel dfm = (DefaultTableModel) resultTable
				.getModel();
		logger.info("Worker update received");
		final SSLData sSLInfo = sslReport.getSslData();

		if (sSLInfo != null) {
			synchronized (dfm) {
				logger.debug("Updating table");
				Object[] values = new Object[] { sSLInfo.getServerName(),
						sSLInfo.getFriendlyName(),
						df.format(sSLInfo.getExpiryDate()), sSLInfo.getIsser() };
				dfm.addRow(values);
				logger.debug("values : " + Arrays.toString(values));
				sslList.add(Arrays.asList(values));
				logger.info("Table updated");
			}
		}

		logger.info("end update");
	}

	class DataTableModel extends DefaultTableModel {

		/**
		 * 
		 */
		private static final long serialVersionUID = 3839763118836071932L;

		public DataTableModel(Object[][] data, Object[] columnNames) {
			super(data, columnNames);
		}

		public DataTableModel() {
		}

		public DataTableModel(Object[] columnNames, int rowCount) {
			super(columnNames, rowCount);
		}

		public DataTableModel(int rowCount, int columnCount) {
			super(rowCount, columnCount);
		}

		@Override
		public boolean isCellEditable(int row, int column) {
			return false;
		}

		@Override
		public void removeRow(int row) {
			super.removeRow(row);
		}

		@Override
		public void setRowCount(int rowCount) {
			super.setRowCount(rowCount);
		}

	}

	private final DateFormat df = new SimpleDateFormat("dd/MM/yyyy  hh:mm:ss a");

	private static final String IPADDRESS_PATTERN = "^([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\."
			+ "([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\."
			+ "([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\."
			+ "([01]?\\d\\d?|2[0-4]\\d|25[0-5])$";

	AtomicInteger counter = new AtomicInteger();

	public void exitSignal() {
		int incrementedCount = counter.incrementAndGet();
		if (incrementedCount == deligateSingleTask) {
			// TODO END
			iconLabel.setVisible(false);
		}
	}
}
