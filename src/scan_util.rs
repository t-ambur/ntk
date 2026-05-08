use rand::seq::SliceRandom;
use std::collections::HashMap;
use std::sync::OnceLock;

// An iterator that can be looped over for either the default randomized port numbers
// Or the range provided by the user (randomized)
pub enum PortIter {
    Range(std::vec::IntoIter<u16>),
    Common(std::array::IntoIter<u16, 1000>),
}

impl PortIter {
    pub fn new(start_range: Option<u16>, end_range: Option<u16>) -> Self {
        if start_range.is_some() || end_range.is_some() {
            let start = start_range.unwrap_or(0);
            let end = end_range.unwrap_or(65535);
            let mut ports: Vec<u16> = (start..=end).collect();
            let mut rng = rand::rng();
            ports.shuffle(&mut rng);
            PortIter::Range(ports.into_iter())
        } else {
            PortIter::Common(randomize_port_scan().into_iter())
        }
    }
}

impl Iterator for PortIter {
    type Item = u16;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            PortIter::Range(range) => range.next(),
            PortIter::Common(iter) => iter.next(),
        }
    }
}

// Below here is just randomized common ports fn and
// a compile time hashmap for name lookup

/// Randomizes an array of the '1000 most commonly used ports' and returns
fn randomize_port_scan() -> [u16; 1000] {
    let mut common_ports = [1,3,4,6,7,9,13,17,19,20,21,22,23,24,25,26,30,32,33,37,42,43,49,53,70,79,80,81,82,83,84,85,88,89,90,99,100,106,109,110,111,113,119,125,135,139,143,144,146,161,163,179,199,211,212,222,254,255,256,259,264,280,301,306,311,340,366,389,406,407,416,417,425,427,443,444,445,458,464,465,481,497,500,512,513,514,515,524,541,543,544,545,548,554,555,563,587,593,616,617,625,631,636,646,648,666,667,668,683,687,691,700,705,711,714,720,722,726,749,765,777,783,787,800,801,808,843,873,880,888,898,900,901,902,903,911,912,981,987,990,992,993,995,999,1000,1001,1002,1007,1009,1010,1011,1021,1022,1023,1024,1025,1026,1027,1028,1029,1030,1031,1032,1033,1034,1035,1036,1037,1038,1039,1040,1041,1042,1043,1044,1045,1046,1047,1048,1049,1050,1051,1052,1053,1054,1055,1056,1057,1058,1059,1060,1061,1062,1063,1064,1065,1066,1067,1068,1069,1070,1071,1072,1073,1074,1075,1076,1077,1078,1079,1080,1081,1082,1083,1084,1085,1086,1087,1088,1089,1090,1091,1092,1093,1094,1095,1096,1097,1098,1099,1100,1102,1104,1105,1106,1107,1108,1110,1111,1112,1113,1114,1117,1119,1121,1122,1123,1124,1126,1130,1131,1132,1137,1138,1141,1145,1147,1148,1149,1151,1152,1154,1163,1164,1165,1166,1169,1174,1175,1183,1185,1186,1187,1192,1198,1199,1201,1213,1216,1217,1218,1233,1234,1236,1244,1247,1248,1259,1271,1272,1277,1287,1296,1300,1301,1309,1310,1311,1322,1328,1334,1352,1417,1433,1434,1443,1455,1461,1494,1500,1501,1503,1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666,1687,1688,1700,1717,1718,1719,1720,1721,1723,1755,1761,1782,1783,1801,1805,1812,1839,1840,1862,1863,1864,1875,1900,1914,1935,1947,1971,1972,1974,1984,1998,1999,2000,2001,2002,2003,2004,2005,2006,2007,2008,2009,2010,2013,2020,2021,2022,2030,2033,2034,2035,2038,2040,2041,2042,2043,2045,2046,2047,2048,2049,2065,2068,2099,2100,2103,2105,2106,2107,2111,2119,2121,2126,2135,2144,2160,2161,2170,2179,2190,2191,2196,2200,2222,2251,2260,2288,2301,2323,2366,2381,2382,2383,2393,2394,2399,2401,2492,2500,2522,2525,2557,2601,2602,2604,2605,2607,2608,2638,2701,2702,2710,2717,2718,2725,2800,2809,2811,2869,2875,2909,2910,2920,2967,2968,2998,3000,3001,3003,3005,3006,3007,3011,3013,3017,3030,3031,3052,3071,3077,3128,3168,3211,3221,3260,3261,3268,3269,3283,3300,3301,3306,3322,3323,3324,3325,3333,3351,3367,3369,3370,3371,3372,3389,3390,3404,3476,3493,3517,3527,3546,3551,3580,3659,3689,3690,3703,3737,3766,3784,3800,3801,3809,3814,3826,3827,3828,3851,3869,3871,3878,3880,3889,3905,3914,3918,3920,3945,3971,3986,3995,3998,4000,4001,4002,4003,4004,4005,4006,4045,4111,4125,4126,4129,4224,4242,4279,4321,4343,4443,4444,4445,4446,4449,4550,4567,4662,4848,4899,4900,4998,5000,5001,5002,5003,5004,5009,5030,5033,5050,5051,5054,5060,5061,5080,5087,5100,5101,5102,5120,5190,5200,5214,5221,5222,5225,5226,5269,5280,5298,5357,5405,5414,5431,5432,5440,5500,5510,5544,5550,5555,5560,5566,5631,5633,5666,5678,5679,5718,5730,5800,5801,5802,5810,5811,5815,5822,5825,5850,5859,5862,5877,5900,5901,5902,5903,5904,5906,5907,5910,5911,5915,5922,5925,5950,5952,5959,5960,5961,5962,5963,5987,5988,5989,5998,5999,6000,6001,6002,6003,6004,6005,6006,6007,6009,6025,6059,6100,6101,6106,6112,6123,6129,6156,6346,6389,6502,6510,6543,6547,6565,6566,6567,6580,6646,6666,6667,6668,6669,6689,6692,6699,6779,6788,6789,6792,6839,6881,6901,6969,7000,7001,7002,7004,7007,7019,7025,7070,7100,7103,7106,7200,7201,7402,7435,7443,7496,7512,7625,7627,7676,7741,7777,7778,7800,7911,7920,7921,7937,7938,7999,8000,8001,8002,8007,8008,8009,8010,8011,8021,8022,8031,8042,8045,8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,8093,8099,8100,8180,8181,8192,8193,8194,8200,8222,8254,8290,8291,8292,8300,8333,8383,8400,8402,8443,8500,8600,8649,8651,8652,8654,8701,8800,8873,8888,8899,8994,9000,9001,9002,9003,9009,9010,9011,9040,9050,9071,9080,9081,9090,9091,9099,9100,9101,9102,9103,9110,9111,9200,9207,9220,9290,9415,9418,9485,9500,9502,9503,9535,9575,9593,9594,9595,9618,9666,9876,9877,9878,9898,9900,9917,9929,9943,9944,9968,9998,9999,10000,10001,10002,10003,10004,10009,10010,10012,10024,10025,10082,10180,10215,10243,10566,10616,10617,10621,10626,10628,10629,10778,11110,11111,11967,12000,12174,12265,12345,13456,13722,13782,13783,14000,14238,14441,14442,15000,15002,15003,15004,15660,15742,16000,16001,16012,16016,16018,16080,16113,16992,16993,17877,17988,18040,18101,18988,19101,19283,19315,19350,19780,19801,19842,20000,20005,20031,20221,20222,20828,21571,22939,23502,24444,24800,25734,25735,26214,27000,27352,27353,27355,27356,27715,28201,30000,30718,30951,31038,31337,32768,32769,32770,32771,32772,32773,32774,32775,32776,32777,32778,32779,32780,32781,32782,32783,32784,32785,33354,33899,34571,34572,34573,35500,38292,40193,40911,41511,42510,44176,44442,44443,44501,45100,48080,49152,49153,49154,49155,49156,49157,49158,49159,49160,49161,49163,49165,49167,49175,49176,49400,49999,50000,50001,50002,50003,50006,50300,50389,50500,50636,50800,51103,51493,52673,52822,52848,52869,54045,54328,55055,55056,55555,55600,56737,56738,57294,57797,58080,60020,60443,61532,61900,62078,63331,64623,64680,65000,65129,65389];
    let mut rng = rand::rng();
    common_ports.shuffle(&mut rng);
    return common_ports;
}

/// Creates a static hashmap mapping common port numbers to their usual process name
pub fn port_map() -> &'static HashMap<u16, &'static str> {
    static MAP: OnceLock<HashMap<u16, &'static str>> = OnceLock::new();
    MAP.get_or_init(|| {
        let mut m = HashMap::new();
        m.insert(1, "TCPMUX");
        m.insert(3, "CompressNET");
        m.insert(4, "Unassigned");
        m.insert(6, "Unassigned");
        m.insert(7, "Echo");
        m.insert(9, "Discard");
        m.insert(13, "Daytime");
        m.insert(17, "Quote of the Day");
        m.insert(19, "Chargen");
        m.insert(20, "FTP Data");
        m.insert(21, "FTP");
        m.insert(22, "SSH");
        m.insert(23, "Telnet");
        m.insert(24, "Priv-mail");
        m.insert(25, "SMTP");
        m.insert(26, "SMTP Alt");
        m.insert(30, "MSG ICP");
        m.insert(32, "MSDPS");
        m.insert(33, "DSP");
        m.insert(37, "Time");
        m.insert(42, "Nameserver");
        m.insert(43, "WHOIS");
        m.insert(49, "TACACS");
        m.insert(53, "DNS");
        m.insert(67, "DHCP Server");
        m.insert(68, "DHCP Client");
        m.insert(69, "TFTP");
        m.insert(70, "Gopher");
        m.insert(79, "Finger");
        m.insert(80, "HTTP");
        m.insert(81, "HTTP Alternate");
        m.insert(82, "HTTP Alternate");
        m.insert(83, "HTTP Alternate");
        m.insert(84, "HTTP Alternate");
        m.insert(85, "HTTP Alternate");
        m.insert(88, "Kerberos");
        m.insert(89, "SU-MIT-TG");
        m.insert(90, "DNSIX");
        m.insert(99, "Metagram Relay");
        m.insert(100, "Newacct");
        m.insert(106, "POP3 Password Change");
        m.insert(109, "POP2");
        m.insert(110, "POP3");
        m.insert(111, "RPCBind");
        m.insert(113, "Ident");
        m.insert(119, "NNTP");
        m.insert(123, "NTP (TCP fallback)");
        m.insert(125, "LOCUS Map");
        m.insert(135, "Microsoft RPC");
        m.insert(137, "NetBIOS Name Service");
        m.insert(138, "NetBIOS Datagram");
        m.insert(139, "NetBIOS Session");
        m.insert(143, "IMAP");
        m.insert(144, "News");
        m.insert(146, "ISO-TP0");
        m.insert(161, "SNMP");
        m.insert(162, "SNMP Trap");
        m.insert(163, "CMIP");
        m.insert(177, "XDMCP");
        m.insert(179, "BGP");
        m.insert(194, "IRC");
        m.insert(199, "SMUX");
        m.insert(211, "ANet");
        m.insert(212, "ANet");
        m.insert(222, "Rsh/RSYNC alt");
        m.insert(255, "Reserved");
        m.insert(389, "LDAP");
        m.insert(406, "IMSP");
        m.insert(407, "Timbuktu");
        m.insert(416, "Silverplatter");
        m.insert(417, "Onmux");
        m.insert(425, "ICAD");
        m.insert(427, "SLP");
        m.insert(443, "HTTPS");
        m.insert(444, "SNPP");
        m.insert(445, "SMB");
        m.insert(458, "QuickTime");
        m.insert(464, "Kerberos Change/Set Password");
        m.insert(465, "SMTPS");
        m.insert(500, "ISAKMP");
        m.insert(512, "Exec");
        m.insert(513, "Login");
        m.insert(514, "Shell");
        m.insert(515, "Printer (LPD)");
        m.insert(520, "RIP");
        m.insert(524, "NCP");
        m.insert(541, "uucp-rlogin");
        m.insert(543, "Kerberos Login");
        m.insert(544, "Kerberos Shell");
        m.insert(545, "AppleShare");
        m.insert(548, "AFP");
        m.insert(554, "RTSP");
        m.insert(555, "DSF");
        m.insert(563, "NNTP over SSL");
        m.insert(587, "SMTP Submission");
        m.insert(591, "FileMaker");
        m.insert(593, "HTTP RPC Ep Map");
        m.insert(616, "SCO Syslog");
        m.insert(617, "SCO DTMgr");
        m.insert(625, "DEC DLM");
        m.insert(631, "IPP");
        m.insert(636, "LDAPS");
        m.insert(646, "LDP");
        m.insert(648, "RRP");
        m.insert(666, "Doom");
        m.insert(667, "Disclose");
        m.insert(668, "Mecomm");
        m.insert(683, "CORBA IIOP");
        m.insert(687, "ASIP Registry");
        m.insert(691, "MS Exchange Routing");
        m.insert(700, "EPP");
        m.insert(705, "AgentX");
        m.insert(711, "Cisco TDP");
        m.insert(714, "NetView");
        m.insert(720, "SMQP");
        m.insert(722, "SCCP");
        m.insert(726, "OMS");
        m.insert(749, "Kerberos Admin");
        m.insert(765, "Webster");
        m.insert(777, "Multiling HTTP");
        m.insert(783, "SpamAssassin");
        m.insert(787, "QSC");
        m.insert(800, "mdbs-daemon");
        m.insert(801, "device");
        m.insert(808, "HTTP Proxy");
        m.insert(843, "Flash Policy");
        m.insert(873, "rsync");
        m.insert(880, "Kerberos");
        m.insert(888, "CDDBP");
        m.insert(898, "Sun Man");
        m.insert(900, "OMGINITIALREFS");
        m.insert(901, "Samba SWAT");
        m.insert(902, "VMware Auth");
        m.insert(903, "VMware Console");
        m.insert(911, "Network Console");
        m.insert(912, "APEX Mesh");
        m.insert(981, "Remote HTTPS");
        m.insert(987, "WebDAV");
        m.insert(989, "FTPS Data");
        m.insert(990, "FTPS");
        m.insert(992, "Telnet over TLS");
        m.insert(993, "IMAPS");
        m.insert(994, "IRC over TLS");
        m.insert(995, "POP3S");
        m.insert(999, "PuTTY Remote");
        m.insert(1000, "Cadlock");
        m.insert(1025, "NFS/IIS/Windows RPC");
        m.insert(1026, "LSA");
        m.insert(1027, "IIS");
        m.insert(1028, "Windows RPC");
        m.insert(1029, "MS LSA");
        m.insert(1030, "RPC");
        m.insert(1080, "SOCKS Proxy");
        m.insert(1110, "NFS Status");
        m.insert(1433, "Microsoft SQL Server");
        m.insert(1434, "MS SQL Monitor");
        m.insert(1521, "Oracle Database");
        m.insert(1720, "H.323");
        m.insert(1723, "PPTP VPN");
        m.insert(1883, "MQTT");
        m.insert(1900, "UPnP SSDP");
        m.insert(2000, "Cisco SCCP");
        m.insert(2001, "DC");
        m.insert(2049, "NFS");
        m.insert(2082, "cPanel");
        m.insert(2083, "cPanel SSL");
        m.insert(2100, "Oracle XDB");
        m.insert(2121, "FTP Alt");
        m.insert(2181, "Zookeeper");
        m.insert(2222, "SSH Alt");
        m.insert(2375, "Docker");
        m.insert(2376, "Docker SSL");
        m.insert(2377, "Docker Swarm");
        m.insert(2483, "Oracle DB SSL");
        m.insert(2484, "Oracle DB");
        m.insert(2601, "Zebra");
        m.insert(2604, "Quagga");
        m.insert(3000, "Dev Web Server");
        m.insert(3001, "Dev Web Server");
        m.insert(3128, "Squid Proxy");
        m.insert(3268, "Global Catalog");
        m.insert(3269, "Global Catalog SSL");
        m.insert(3306, "MySQL");
        m.insert(3389, "RDP");
        m.insert(3478, "STUN");
        m.insert(3690, "Subversion");
        m.insert(4000, "ICQ");
        m.insert(4444, "Metasploit");
        m.insert(4567, "Rails Dev");
        m.insert(4662, "eDonkey");
        m.insert(5000, "UPnP / Dev Server");
        m.insert(5001, "HTTPS Alt");
        m.insert(5060, "SIP");
        m.insert(5061, "SIP TLS");
        m.insert(5080, "Asterisk");
        m.insert(5432, "PostgreSQL");
        m.insert(5601, "Kibana");
        m.insert(5666, "NRPE");
        m.insert(5672, "AMQP");
        m.insert(5800, "VNC Web");
        m.insert(5900, "VNC");
        m.insert(5901, "VNC Display 1");
        m.insert(5902, "VNC Display 2");
        m.insert(5903, "VNC Display 3");
        m.insert(5904, "VNC Display 4");
        m.insert(5985, "WinRM HTTP");
        m.insert(5986, "WinRM HTTPS");
        m.insert(6000, "X11");
        m.insert(6001, "X11 Display 1");
        m.insert(6002, "X11 Display 2");
        m.insert(6003, "X11 Display 3");
        m.insert(6004, "X11 Display 4");
        m.insert(6005, "X11 Display 5");
        m.insert(6379, "Redis");
        m.insert(6443, "Kubernetes API");
        m.insert(6667, "IRC");
        m.insert(7000, "WebLogic");
        m.insert(7001, "WebLogic Admin");
        m.insert(7070, "RealServer");
        m.insert(7199, "Cassandra");
        m.insert(7200, "Elastic");
        m.insert(7443, "HTTPS Alt");
        m.insert(8000, "HTTP Alt");
        m.insert(8008, "HTTP Alt (Google)");
        m.insert(8009, "AJP13");
        m.insert(8010, "HTTP Alt");
        m.insert(8080, "HTTP Proxy");
        m.insert(8081, "HTTP Alt");
        m.insert(8082, "HTTP Alt");
        m.insert(8083, "HTTP Alt");
        m.insert(8084, "HTTP Alt");
        m.insert(8085, "HTTP Alt");
        m.insert(8086, "InfluxDB");
        m.insert(8087, "HTTP Alt");
        m.insert(8088, "HTTP Alt");
        m.insert(8089, "Splunk");
        m.insert(8090, "HTTP Alt");
        m.insert(8181, "HTTP Alt");
        m.insert(8200, "Vault");
        m.insert(8222, "VMware");
        m.insert(8333, "Bitcoin");
        m.insert(8400, "RTSP Alt");
        m.insert(8443, "HTTPS Alt");
        m.insert(8500, "Consul");
        m.insert(8600, "Consul DNS");
        m.insert(8880, "HTTP Alt");
        m.insert(8881, "HTTP Alt");
        m.insert(8882, "HTTP Alt");
        m.insert(8883, "Secure MQTT");
        m.insert(8884, "HTTP Alt");
        m.insert(8885, "HTTP Alt");
        m.insert(8888, "HTTP Alt");
        m.insert(8899, "HTTP Alt");
        m.insert(9000, "SonarQube / PHP-FPM");
        m.insert(9001, "Tor");
        m.insert(9042, "Cassandra");
        m.insert(9050, "Tor SOCKS");
        m.insert(9080, "HTTP Alt");
        m.insert(9090, "Prometheus");
        m.insert(9100, "JetDirect");
        m.insert(9200, "Elasticsearch");
        m.insert(9418, "Git");
        m.insert(9443, "HTTPS Alt");
        m.insert(9999, "Abyss Web Server");
        m.insert(10000, "Webmin");
        m.insert(10250, "Kubernetes Kubelet");
        m.insert(10255, "Kubelet Readonly");
        m.insert(11211, "Memcached");
        m.insert(24800, "Synergy");
        m.insert(27018, "MongoDB Alt");
        m.insert(27019, "MongoDB Config");
        m.insert(28017, "MongoDB Web");
        m.insert(32768, "RPC High Port");
        m.insert(32769, "RPC High Port");
        m.insert(32770, "RPC High Port");
        m.insert(32771, "RPC High Port");
        m.insert(32772, "RPC High Port");
        m.insert(32773, "RPC High Port");
        m.insert(32774, "RPC High Port");
        m.insert(32775, "RPC High Port");
        m.insert(32776, "RPC High Port");
        m.insert(32777, "RPC High Port");
        m.insert(32778, "RPC High Port");
        m.insert(32779, "RPC High Port");
        m.insert(32780, "RPC High Port");
        m.insert(32781, "RPC High Port");
        m.insert(32782, "RPC High Port");
        m.insert(32783, "RPC High Port");
        m.insert(32784, "RPC High Port");
        m.insert(32785, "RPC High Port");
        m.insert(49152, "Dynamic / Ephemeral Port");
        m.insert(49153, "Dynamic / Ephemeral Port");
        m.insert(49154, "Dynamic / Ephemeral Port");
        m.insert(49155, "Dynamic / Ephemeral Port");
        m.insert(49156, "Dynamic / Ephemeral Port");
        m.insert(49157, "Dynamic / Ephemeral Port");
        m.insert(49158, "Dynamic / Ephemeral Port");
        m.insert(49159, "Dynamic / Ephemeral Port");
        m.insert(49160, "Dynamic / Ephemeral Port");
        m.insert(49161, "Dynamic / Ephemeral Port");
        m.insert(49163, "Dynamic / Ephemeral Port");
        m.insert(49165, "Dynamic / Ephemeral Port");
        m.insert(49167, "Dynamic / Ephemeral Port");
        m.insert(49175, "Dynamic / Ephemeral Port");
        m.insert(49176, "Dynamic / Ephemeral Port");
        m.insert(50000, "DB2");
        m.insert(50070, "Hadoop NameNode");
        m.insert(50075, "Hadoop DataNode");
        m.insert(50090, "Hadoop Secondary NameNode");
        m.insert(50389, "LDAP Alternate");
        m.insert(50636, "LDAPS Alternate");
        m.insert(55555, "Common Dev/Test Port");
        m.insert(58080, "HTTP Alternate");
        m.insert(60443, "HTTPS Alternate High Port");
        m.insert(62078, "iPhone Sync (lockdown)");
        m.insert(65389, "LDAP Alternate High Port");
        m
    })
}
