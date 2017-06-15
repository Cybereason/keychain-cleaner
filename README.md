# keychain-cleaner

[![cybereason](https://image.ibb.co/evrPtF/Cybereason_pb.png)](https://www.cybereason.com/)

Written by Shir Yerushalmi of Cybereason.

**keychain-cleaner** is a command line tool designed to bridge a gap in the OSX 'security' command line, which does not enable the "clean deletion" of a keychain certificate along with its private key.
- When approaching this issue and investigating the 'security' cmd source code, we saw that when the tool is deleting a certificate ('delete-certificate' option), its related private key (if there is one) stays in the keychain. There was no way to delete the private key itself via command line.

- In extreme cases, when an application imports the certificate (for SSL verification, for example) it should give itself (and only itself) the permission to use the private key. Upon upgrade (or any modification that changes the codesign of the application) and an attempt to use the private key, the keychain identifies the situation and the result will be an ugly pop-up for the user, prompting a request for password in the worst case (or a behind-the-scenes failure in the best case).

- This issue is resolved by Apple's update 'Security-57740.51.3', which relates to 'macOS 10.12.4'. In this version, the 'security' cmd first introduces the 'delete-identity' option, and practically solves the issue for future OSs. 
On any pervious OS (or need to be backwards compatible with such OS), feel free to use this tool/code and tweak it to your specific needs.

- Many of the answers we found online suggested deleting of the private key via the Keychain Access UI (which does not align with any automation process, and is not acceptable for any application that should manage its installation / upgrade process) or just leave the private key dangled behind, which can result in many unused keys wandering around the keychain desert for all eternity, but can also cause unintended and unapproved 're-use' for the key.

- When deleting a 'trusted' certificate, this tool will also remove the related trust object (this functionality can be achieved also using the 'security' cmd).

# Usage
- Run as root ('sudo')
- keychain-cleaner [certificate label] (as appears in the Keychain Access UI)
- The tool assumes that the certificate you passed as a parameter is unique by its label (searches in all available keychains) and deletes only one. In case you have the same certificate, for example, in both System and Login keychains, you can run this tool twice. In any other case where a more sophisticated logic is needed, look for the comments inside and change accordingly.

# Licensing
keychain-cleaner is licensed under the AGPL license. Please see LICENSE.MD file for more details.
