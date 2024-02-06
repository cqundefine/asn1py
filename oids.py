commonOIDs: dict[str, str] = {
    "1.2.840.113549.1.1.1": "rsaEncryption",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.3.6.1.5.5.7.1.1": "authorityInfoAccess",
    "2.5.4.3": "commonName",    
    "2.5.4.6": "countryName",
    "2.5.4.10": "organizationName",
    "2.5.29.15": "keyUsage",
    "2.5.29.19": "basicConstraints",
    "2.5.29.32": "certificatePolicies",
}

COMMON_NAME_OID = "2.5.4.3"
COUNTRY_NAME_OID = "2.5.4.6"
ORGANIZATION_NAME_OID = "2.5.4.10"