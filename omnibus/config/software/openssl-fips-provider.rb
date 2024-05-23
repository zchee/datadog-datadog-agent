# Unless explicitly stated otherwise all files in this repository are licensed
# under the Apache License Version 2.0.
# This product includes software developed at Datadog (https:#www.datadoghq.com/).
# Copyright 2016-present Datadog, Inc.

name "openssl-fips-provider"
default_version "0.0.1"

OPENSSL_FIPS_MODULE_VERSION="3.0.8"
OPENSSL_FIPS_MODULE_FILENAME="openssl-#{OPENSSL_FIPS_MODULE_VERSION}.tar.gz"
OPENSSL_FIPS_MODULE_SHA256_SUM="6c13d2bf38fdf31eac3ce2a347073673f5d63263398f1f69d0df4a41253e4b3e"


build do
    source url: "https://www.openssl.org/source/#{OPENSSL_FIPS_MODULE_FILENAME}",
           sha256: "#{OPENSSL_FIPS_MODULE_SHA256_SUM}",
           extract: :seven_zip,
           target_filename: "openssl-fips-provider.tar.gz"
    
    command "tar -xvf openssl-fips-provider.tar.gz"
    command "cd openssl-#{OPENSSL_FIPS_MODULE_VERSION}"
    # Exact build steps from security policy:
    # https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp4282.pdf
    #
    # ---------------- DO NOT MODIFY LINES BELOW HERE ----------------
    command "./Configure enable-fips"

    command "make"
    command "make install"
    # ---------------- DO NOT MODIFY LINES ABOVE HERE ----------------
end 