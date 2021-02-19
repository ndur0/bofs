#pragma once

#include <windows.h>
#include <stdio.h>
#include <winldap.h>
#include <winber.h>

// API Imports required in BOF 
DECLSPEC_IMPORT DWORD WINAPI NETAPI32$DsGetDcNameA(LPVOID, LPVOID, LPVOID, LPVOID, ULONG, LPVOID);
DECLSPEC_IMPORT DWORD WINAPI NETAPI32$NetApiBufferFree(LPVOID);
WINBASEAPI BOOLEAN WINAPI SECUR32$GetUserNameExA (int NameFormat, LPSTR lpNameBuffer, PULONG nSize);
WINLDAPAPI ULONG LDAPAPI WLDAP32$ldap_bind_s(LDAP *ld,const PCHAR dn,const PCHAR cred,ULONG method);
WINLDAPAPI LDAP *LDAPAPI WLDAP32$ldap_init(PSTR HostName,ULONG PortNumber);
WINLDAPAPI ULONG LDAPAPI WLDAP32$ldap_unbind_s(LDAP *ld);
WINLDAPAPI ULONG LDAPAPI WLDAP32$ldap_modify_s(LDAP *ld, PSTR dn, LDAPModA *mods[]);
WINLDAPAPI PCHAR LDAPAPI WLDAP32$ldap_err2string(ULONG err);
DECLSPEC_IMPORT PCHAR __cdecl MSVCRT$strstr(const char *_Str, const char *_SubStr);
WINBASEAPI BOOLEAN WINAPI SECUR32$TranslateNameA (LPCSTR lpAccountName, EXTENDED_NAME_FORMAT AccountNameFormat, EXTENDED_NAME_FORMAT DesiredNameFormat, LPSTR lpTranslatedName, PULONG nSize);
WINLDAPAPI ULONG LDAPAPI WLDAP32$ldap_search_s(LDAP *ld,PCHAR base,ULONG scope,PCHAR filter,PCHAR attrs[],ULONG attrsonly,LDAPMessage **res);
WINLDAPAPI ULONG LDAPAPI WLDAP32$ldap_count_entries(LDAP*,LDAPMessage*);
WINLDAPAPI struct berval **LDAPAPI WLDAP32$ldap_get_values_lenA (LDAP *ExternalHandle,LDAPMessage *Message,const PCHAR attr);
WINLDAPAPI LDAPMessage*  LDAPAPI WLDAP32$ldap_first_entry(LDAP *ld,LDAPMessage *res);
WINLDAPAPI LDAPMessage*  LDAPAPI WLDAP32$ldap_next_entry(LDAP*,LDAPMessage*);
WINLDAPAPI ULONG LDAPAPI WLDAP32$ldap_value_free(PCHAR *);
WINLDAPAPI PCHAR LDAPAPI WLDAP32$ldap_next_attribute(LDAP *ld,LDAPMessage *entry,BerElement *ptr);
WINLDAPAPI VOID LDAPAPI WLDAP32$ldap_memfree(PCHAR);
WINLDAPAPI ULONG LDAPAPI WLDAP32$ldap_msgfree(LDAPMessage*);
WINLDAPAPI PCHAR LDAPAPI WLDAP32$ldap_first_attribute(LDAP *ld,LDAPMessage *entry,BerElement **ptr);
WINLDAPAPI PCHAR * LDAPAPI WLDAP32$ldap_get_values(LDAP *ld,LDAPMessage *entry,const PSTR attr);
WINLDAPAPI ULONG LDAPAPI WLDAP32$ldap_count_values(PCHAR *vals);
WINLDAPAPI VOID LDAPAPI WLDAP32$ber_free(BerElement *pBerElement,INT fbuf);
