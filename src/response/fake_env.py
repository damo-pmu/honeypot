"""Fake environment generator - creates decoy responses"""
import os
import random
from typing import Dict, List, Optional
from pathlib import Path
from pydantic import BaseModel


class FakeFile(BaseModel):
    """Represents a fake file in the decoy environment"""
    path: str
    content: str
    size_kb: int = 1
    mimetype: str = "text/plain"


class DecoyEnvironment(BaseModel):
    """Generated decoy environment"""
    template_name: str
    files: List[FakeFile]
    hostname: str
    os_type: str
    services: List[str]


def generate_cisco_decoy(interaction_level: int = 0) -> DecoyEnvironment:
    """Generate Cisco router decoy environment"""
    files = [
        FakeFile(
            path="/show/version",
            content="Cisco IOS Software, Version 15.2(2)E6\nCompiled 6-Apr-23\nSystem uptime: 12 weeks, 3 days, 4 hours",
            size_kb=2
        ),
        FakeFile(
            path="/show/running-config",
            content="hostname switch-access\ninterface vlan 10\n ip address 192.168.10.1 255.255.255.0\n!",
            size_kb=15
        ),
        FakeFile(
            path="/show/arp",
            content="Protocol  Address          Age  Hardware\nInternet  192.168.10.10    5    0011.2233.4455\nInternet  192.168.10.20    3    00aa.bbcc.dd11",
            size_kb=4
        )
    ]
    
    if interaction_level > 5:
        files.append(FakeFile(
            path="/show/cdp",
            content="Device ID: core-switch.domain.local\nIP address: 10.0.0.1\nPlatform: cisco WS-C3750X",
            size_kb=3
        ))
    
    return DecoyEnvironment(
        template_name="cisco_router",
        files=files,
        hostname=f"switch-{random.randint(10,99)}",
        os_type="Cisco IOS",
        services=["SSH", "Telnet", "SNMP"]
    )


def generate_windows_decoy(interaction_level: int = 0) -> DecoyEnvironment:
    """Generate Windows server decoy environment"""
    files = [
        FakeFile(
            path="C:\\Windows\\System32\\config\\SAM",
            content="Administrator:500:aad3b435b51404eeaad3b435b51404ee:32ed87bdb5fdc5e9cba88547376818d4:::",
            size_kb=500,
            mimetype="application/octet-stream"
        ),
        FakeFile(
            path="C:\\inetpub\\wwwroot\\web.config",
            content="<?xml version=\"1.0\"?><configuration><connectionStrings><add name=\"DB\" connectionString=\"Server=db.internal;User=admin;Password=SuperSecret123!\"/></connectionStrings></configuration>",
            size_kb=8
        ),
        FakeFile(
            path="C:\\Users\\Administrator\\Desktop\\notes.txt",
            content="TODO: Change password before vacation\nOld: admin123\nNew: Summer2024!",
            size_kb=1
        )
    ]
    
    if interaction_level > 3:
        files.append(FakeFile(
            path="C:\\secrets\\backup_keys.txt",
            content="ssh-rsa AAAAB3NzaC1yc2E... fake-key-for-attacker",
            size_kb=2
        ))
    
    return DecoyEnvironment(
        template_name="windows_server",
        files=files,
        hostname=f"WIN-SVR-{random.randint(1000,9999)}",
        os_type="Windows Server 2019",
        services=["RDP", "SMB", "WinRM"]
    )


def generate_jenkins_decoy() -> DecoyEnvironment:
    """Generate Jenkins CI server decoy"""
    files = [
        FakeFile(
            path="/var/lib/jenkins/config.xml",
            content="""<hudson><disabled>false</disabled><numExecutors>4</numExecutors>
<views><url>login</url></views>
<useSecurity>true</useSecurity>
<authorizationStrategy class=\"hudson.security.FullControlOnceLoggedInAuthorizationStrategy\"/>""",
            size_kb=5
        ),
        FakeFile(
            path="/var/lib/jenkins/users/admin/config.xml", 
            content="<passwordHash>#jbcrypt:pass123</passwordHash>",
            size_kb=2
        ),
        FakeFile(
            path="/var/lib/jenkins/secrets/master.key",
            content="FAKE_KEY_FOR_ATTAcker_DO_NOT_USE_IN_PRODUCTION",
            size_kb=1,
            mimetype="application/octet-stream"
        )
    ]
    
    return DecoyEnvironment(
        template_name="jenkins_ci",
        files=files,
        hostname=f"jenkins-{random.randint(1,50)}",
        os_type="Linux (Ubuntu)",
        services=["HTTP", "SSH", "Docker"]
    )


def get_decoy_by_template(template: str, interaction_level: int = 0) -> Optional[DecoyEnvironment]:
    """Get decoy environment by template name"""
    generators = {
        "cisco_router": generate_cisco_decoy,
        "windows_server": generate_windows_decoy,
        "jenkins_ci": generate_jenkins_decoy
    }
    
    generator = generators.get(template)
    if generator:
        return generator(interaction_level)
    return None


# Safe credential patterns (obviously fake)
SAFE_CREDENTIALS = [
    "admin:Password123!",
    "root:toor",
    "user:changeme",
    "Administrator:Summer2024!",
    "backup:B@ckupKey2024"
]