Playstation Mobile Development Assistant Signer Tools
===============================================================================

These utilities allows generation of locally signed PSMDA cache contents.

## revoke_sign

Takes [NSXVID-PSS.VT.WW-GLOBAL.xml](https://nsx.sec.np.dl.playstation.net/nsx/sec/Xz78TMQ1Uf31VCYr/c/NSXVID/NSXVID-PSS.VT.WW-GLOBAL.xml) 
revocation file and locally signs it with the current (local) date. This bypasses the download of the XML from PSN 
servers upon PSMDA launch.

## kconsole_sign

The kconsole cache is found in ux0:cache/PCSI00007/_System/protected_kconsole_cache.dat and contains the keystore for 
access the application keys that PSM SDK uses. This utility takes this file and patches it with an expire timestamp 
that is maximum, allowing any valid app key to be used without expiry.
