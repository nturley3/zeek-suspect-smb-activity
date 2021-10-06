Suspicious SMB Activity Detection
======================

Bro module which detects suspicious activity over SMB v1 and v2 protocols.

Installation/Upgrade
------------

This is easiest to install through the Bro package manager::

	bro-pkg refresh
	bro-pkg install https://github.com/nturley3/zeek-suspect-smb-activity

If you need to upgrade the package::

	bro-pkg refresh
	bro-pkg upgrade https://github.com/nturley3/zeek-suspect-smb-activity

Usage
-----

This script generates the following notices: 

**SMBSuspectActivity::Admin_Share_Suspicious_UNC** - Suspicious access to an Adminstrative UNC share was detected. 

**SMBSuspectActivity::Admin_Share_Wannacry_Beacon** - UNC IP and path connection attempts indicative of a WannaCry infected system beaconing.

**SMBSuspectActivity::SMB1_Transaction2_Reserved_Cmd_Usage** - Detect attempted usage of SMB1 Transaction2 SESSION_SETUP calls which is indicative of infection attempts for EternalBlue
and DoublePulsar. See https://cloudblogs.microsoft.com/microsoftsecure/2017/06/30/exploring-the-crypt-analysis-of-the-wannacrypt-ransomware-smb-exploit-propagation/.

**SMBSuspectActivity::Address_Scan_Access_Denied** - 

**SMBSuspectActivity::SMB1_Transaction2_Reserved_Cmd_Usage** - This indicates that an HTTP server was
