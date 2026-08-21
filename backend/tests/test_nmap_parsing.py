"""
nmap XML parsing. The fixture below is genuine nmap -oX output structure; the
parser must extract exactly what is present and invent nothing that is not.
"""
from app.services.network_scanner import _parse_nmap_xml

NMAP_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.94">
  <host>
    <status state="up" reason="arp-response"/>
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Dell Inc."/>
    <hostnames><hostname name="fileserver.local" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9p1"/>
      </port>
      <port protocol="tcp" portid="445">
        <state state="open"/>
        <service name="microsoft-ds"/>
        <script id="smb-vuln-ms17-010" output="VULNERABLE: Remote Code Execution"/>
      </port>
      <port protocol="tcp" portid="8080">
        <state state="closed"/>
        <service name="http-proxy"/>
      </port>
    </ports>
    <os>
      <osmatch name="Linux 5.4 - 5.15" accuracy="96"/>
    </os>
    <hostscript>
      <script id="smb2-security-mode" output="Message signing enabled but not required"/>
    </hostscript>
  </host>
  <host>
    <status state="down" reason="no-response"/>
    <address addr="192.168.1.11" addrtype="ipv4"/>
  </host>
</nmaprun>
"""


def test_only_hosts_that_are_up_are_returned():
    hosts = _parse_nmap_xml(NMAP_XML)
    assert len(hosts) == 1
    assert hosts[0].ip_address == "192.168.1.10"


def test_host_attributes_are_extracted_verbatim():
    host = _parse_nmap_xml(NMAP_XML)[0]
    assert host.hostname == "fileserver.local"
    assert host.mac_address == "AA:BB:CC:DD:EE:FF"
    assert host.vendor == "Dell Inc."
    assert host.os_match == "Linux 5.x"


def test_only_open_ports_are_returned():
    host = _parse_nmap_xml(NMAP_XML)[0]
    assert sorted(port.port for port in host.ports) == [22, 445]


def test_service_banner_is_preserved():
    host = _parse_nmap_xml(NMAP_XML)[0]
    ssh = next(port for port in host.ports if port.port == 22)
    assert ssh.service == "ssh"
    assert ssh.product == "OpenSSH"
    assert ssh.version == "8.9p1"


def test_port_and_host_scripts_are_captured():
    host = _parse_nmap_xml(NMAP_XML)[0]
    smb = next(port for port in host.ports if port.port == 445)
    assert [script.id for script in smb.scripts] == ["smb-vuln-ms17-010"]
    assert "VULNERABLE" in smb.scripts[0].output
    assert [script.id for script in host.scripts] == ["smb2-security-mode"]


def test_empty_scan_yields_no_hosts():
    assert _parse_nmap_xml('<?xml version="1.0"?><nmaprun/>') == []
