/* 
 * Copyright (C) 2017, Cybereason
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <Security/Security.h>

/*!
 @function SecCertificateCopyCertificateByLabel
 @abstract Returns the certificate with the input label from the keychain.
 @param certLabel The certificate's label (as appear on Keychain Access UI).
 @result The corresponding certificate from the keychain. Releasing the 
 return value is the caller's responsibility.
*/
SecCertificateRef SecCertificateCopyCertificateByLabel(const char * certLabel)
{
    // The way to look security items (certificates, keys, identities,
    // passwords...) in the keychain can be done by SecItemCopyMatching, who
    //gets a list of parameters for filtering (as a dictionary) and returns
    // the corresponding item/s
    CFMutableDictionaryRef propertyMatchDict = CFDictionaryCreateMutable(kCFAllocatorDefault , 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(propertyMatchDict, kSecClass, kSecClassCertificate);
    CFDictionarySetValue(propertyMatchDict, kSecReturnRef, kCFBooleanTrue);
    CFStringRef cfCertLabel = CFStringCreateWithCString(kCFAllocatorDefault, certLabel, kCFStringEncodingMacRoman);
    CFDictionarySetValue(propertyMatchDict, kSecAttrLabel, cfCertLabel);
    
    // This tool is designed to delete a certificate with a unique label accross all
    // keychains (usually login & system), in case of 2 (or more) certificates with the
    // same label, this method will result with the first it finds...
    // If you want to get all the certificates with the label -
    //     1. Add the line CFDictionarySetValue(propertyMatchDictForCert, kSecMatchLimit, kSecMatchLimitAll);
    //     2. Expect 'item' variable will be CFArray (instead of SecCertificateRef)
    //     3. Add the logic that will distinguish between the certificates in the array and will return the
    //        one you want to delete.
    
    CFTypeRef item = NULL;
    OSStatus status = SecItemCopyMatching(propertyMatchDict, &item);
    CFRelease(propertyMatchDict);
    CFRelease(cfCertLabel);
    if (status != errSecSuccess || SecCertificateGetTypeID() != CFGetTypeID(item))
    {
        if (status == errSecItemNotFound)
        {
            printf("Certificate '%s' not found in keychain. Aborting.\n", certLabel);
        }
        else
        {
            printf("Could not find certificate '%s' in the keychain (OSStatus %d). Aborting.\n", certLabel, status);
        }
        return NULL;
    }
    
    return (SecCertificateRef)item;
}

void deleteTrustIfExists(const SecCertificateRef * certificate)
{
    static const SecTrustSettingsDomain domains[] = {kSecTrustSettingsDomainSystem, kSecTrustSettingsDomainAdmin, kSecTrustSettingsDomainUser};
    static const char * domainsString[] = {"Domain System", "Domain Admin", "Domain User"};
    
    for (int i = 0; i < 3; ++i)
    {
        CFArrayRef trustSettings = NULL;
        OSStatus status = SecTrustSettingsCopyTrustSettings(*certificate, domains[i], &trustSettings);
        if (status != errSecItemNotFound)
        {
            status = SecTrustSettingsRemoveTrustSettings(*certificate, domains[i]);
            if (status == errSecSuccess)
            {
                printf("Deleted certificate's trust settings (%s)...\n", domainsString[i]);
            }
            else
            {
                printf("Certificate's trust settings found (%s) but could not be deleted (OSStatus %d). Continuing.\n", domainsString[i], status);
            }
        }
        
        if (trustSettings)
        {
            CFRelease(trustSettings);
        }
    }
}

bool deleteCertificate(const SecCertificateRef* certificate)
{
    // Delete trust settings - if any -
    deleteTrustIfExists(certificate);
    
    SecIdentityRef identity = NULL;
    OSStatus status = SecIdentityCreateWithCertificate(NULL, *certificate, &identity);
    if (status != errSecItemNotFound) // If an identity can't be created - there's no private key
    {
        if (status != errSecSuccess)
        {
            printf("FAILURE: Could not get identity for certificate (OSStatus %d). Aborting.\n", status);
            return false;
        }
        
        // Obtain the private key and delete it:
        SecKeyRef privateKey = NULL;
        status = SecIdentityCopyPrivateKey(identity, &privateKey);
        CFRelease(identity);
        if (status == errSecSuccess)
        {
            status = SecKeychainItemDelete((SecKeychainItemRef)privateKey);
            CFRelease(privateKey);
            if (status != errSecSuccess)
            {
                printf("FAILURE: Failed deleting private key from certificate (OSStatus %d). Aborting.\n", status);
                return false;
            }
            
            printf("Deleted certificate's private key...\n");
        }
    }
    
    // Delete the certificate itself:
    status = SecKeychainItemDelete((SecKeychainItemRef)*certificate);
    if (status != errSecSuccess)
    {
        if (status == errSecWrPerm)
        {
            printf("FAILURE: Failed deleting certificate - no permissions, run this tool as root ('sudo'). Aborting.\n");
            return false;
        }
        
        printf("FAILURE: Failed deleting certificate (OSStatus %d). Aborting.\n", status);
        return false;
    }
    
    printf("Deleted certificate from keychain successfully...\n");
    return true;
}

/*!
 @function main
 @abstract Deletes a certificate from the keychain along with its related 
 item (private key or trust)
 @param argc Must be 2 (gets one parameter).
 @param argv A single string identifying the certificate label to delete (as
 appears in the Keychain Access ui)
 @result A result code. 0 - indicates deletion success (or no deletion since 
 the certificate wasn't present in the first place), 1 - Certificate was found
 and deletion failed.
 @discussion In case of a failure, this utility will log an explenation or the
 OSStatus error code prevented the deletion, meaning of the error code can be
 found online (try https://www.osstatus.com/ and if multiple answers appear, 
 concentrate on the one from 'Security' framework)
 */
int main(int argc, const char * argv[]) {
    
    if (argc != 2)
    {
        printf("Certificate label not provided as argument.\nUsage: keychain-cleaner certificate-label\n");
        return 1;
    }
    
    SecCertificateRef certificate = SecCertificateCopyCertificateByLabel(argv[1]);
    if (certificate == NULL)
    {
        // If you want the tool to return an error code if it tries to delete a certificate
        // that dosen't exist in the keychain - change the return value here:
        return 0;
    }
    
    bool deletionSuccess = deleteCertificate(&certificate);
    CFRelease(certificate);
    if (!deletionSuccess)
    {
        return 1;
    }
    
    // Note: in this case Keychain Access UI is not updated immediately. In order to verify reopen
    // it or use 'security dump-keychain' in terminal
    return 0;
}
