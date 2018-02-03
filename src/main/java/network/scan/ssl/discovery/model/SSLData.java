package network.scan.ssl.discovery.model;

import java.util.Date;

/**
 *  Retrieved SSL information
 * 
 * @author Maninder Singh Jheeta
 */
public class SSLData {
    private String serverName;
    private String isser;
    private Date expiryDate;
    private String serialNumber;
    private String friendlyName;

    public String getFriendlyName() {
        return friendlyName;
    }

    public void setFriendlyName(String friendlyName) {
        this.friendlyName = friendlyName;
    }

    public Date getExpiryDate() {
        return expiryDate;
    }

    public void setExpiryDate(Date expiryDate) {
        this.expiryDate = expiryDate;
    }

    public String getIsser() {
        return isser;
    }

    public void setIsser(String isser) {
        this.isser = isser;
    }

    public String getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(String serialNumber) {
        this.serialNumber = serialNumber;
    }

    public String getServerName() {
        return serverName;
    }

    public void setServerName(String serverName) {
        this.serverName = serverName;
    }
    @Override
    public String toString() {
    	return new StringBuilder().append(isser).append(" : ").append(expiryDate).toString();
    }
}
