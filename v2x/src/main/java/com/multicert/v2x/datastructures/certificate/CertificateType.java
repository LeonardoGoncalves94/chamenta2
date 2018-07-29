package com.multicert.v2x.datastructures.certificate;

import com.multicert.v2x.asn1.coer.COEREnumerationType;

public enum  CertificateType implements COEREnumerationType
{
    explicit,
    implicit //not used in ETSI 103 097
}

