#!/usr/bin/env sh
# Synthetic trust-list fixtures for the trust-list importers (agent A). NO REAL CA DATA: every provider, service
# and certificate here is invented, or is the Rakvor lab root / lab TSA of tests/fixtures/openssl.
#
#   tests/fixtures/trustlists/make.sh        writes the invented CA certificates when missing, then the files:
#     invented-ca-eu.crt, invented-ecd-co.crt  self-signed EC P-256 certificates (random keys, 10 years from the
#                     day they were made; kept once made)
#     tl-sample.xml   ETSI TS 119 612 national TL (territory XX): 2 TSPs, 2 services, status history, lab root
#                     + lab TSA + the invented EU CA as digital identities
#     co-sample.csv   curated Colombian CSV: 2 invented ECDs (one with a suspension period), the lab root and
#                     the invented Colombian CA
set -eu
here=$(cd "$(dirname "$0")" && pwd)
ossl="$here/../openssl"
cd "$here"
mk() { # name subject
  [ -f "$1.crt" ] && return 0
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout /dev/null -subj "$2" \
    -days 3650 -addext "basicConstraints=critical,CA:true" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" -out "$1.crt" 2>/dev/null
}
mk invented-ca-eu "/C=XX/O=Invented Trust Services Ltd/CN=Invented Qualified CA 1"
mk invented-ecd-co "/C=CO/O=Ejemplo ECD Inventada S.A.S./CN=Ejemplo ECD Inventada CA Firma Digital"
b64() { openssl x509 -in "$1" -outform DER | openssl base64 -A; }
ROOT=$(b64 "$ossl/root.crt"); TSA=$(b64 "$ossl/tsa.crt"); EU=$(b64 invented-ca-eu.crt); CO=$(b64 invented-ecd-co.crt)
S=http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus
cat > tl-sample.xml <<XML
<?xml version="1.0" encoding="UTF-8"?>
<!-- SYNTHETIC test trust list (ETSI TS 119 612 shape). Invented providers; not a real TL. Not signed. -->
<tsl:TrustServiceStatusList xmlns:tsl="http://uri.etsi.org/02231/v2#" TSLTag="http://uri.etsi.org/19612/TSLTag">
  <tsl:SchemeInformation>
    <tsl:TSLVersionIdentifier>5</tsl:TSLVersionIdentifier>
    <tsl:TSLSequenceNumber>7</tsl:TSLSequenceNumber>
    <tsl:SchemeTerritory>XX</tsl:SchemeTerritory>
    <tsl:ListIssueDateTime>2026-10-01T00:00:00Z</tsl:ListIssueDateTime>
    <tsl:NextUpdate><tsl:dateTime>2027-04-01T00:00:00Z</tsl:dateTime></tsl:NextUpdate>
  </tsl:SchemeInformation>
  <tsl:TrustServiceProviderList>
    <tsl:TrustServiceProvider>
      <tsl:TSPInformation><tsl:TSPName><tsl:Name xml:lang="xx">Proveedor Inventado</tsl:Name><tsl:Name xml:lang="en">Rakvor Lab Synthetic TSP</tsl:Name></tsl:TSPName></tsl:TSPInformation>
      <tsl:TSPServices>
        <tsl:TSPService>
          <tsl:ServiceInformation>
            <tsl:ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</tsl:ServiceTypeIdentifier>
            <tsl:ServiceName><tsl:Name xml:lang="en">Rakvor Lab Root CA (synthetic QC service)</tsl:Name></tsl:ServiceName>
            <tsl:ServiceDigitalIdentity><tsl:DigitalId><tsl:X509Certificate>$ROOT</tsl:X509Certificate></tsl:DigitalId></tsl:ServiceDigitalIdentity>
            <tsl:ServiceStatus>$S/withdrawn</tsl:ServiceStatus>
            <tsl:StatusStartingTime>2026-09-01T00:00:00Z</tsl:StatusStartingTime>
          </tsl:ServiceInformation>
          <tsl:ServiceHistory>
            <tsl:ServiceHistoryInstance>
              <tsl:ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</tsl:ServiceTypeIdentifier>
              <tsl:ServiceName><tsl:Name xml:lang="en">Rakvor Lab Root CA (synthetic QC service)</tsl:Name></tsl:ServiceName>
              <tsl:ServiceStatus>$S/granted</tsl:ServiceStatus>
              <tsl:StatusStartingTime>2025-01-01T00:00:00Z</tsl:StatusStartingTime>
            </tsl:ServiceHistoryInstance>
          </tsl:ServiceHistory>
        </tsl:TSPService>
        <tsl:TSPService>
          <tsl:ServiceInformation>
            <tsl:ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST</tsl:ServiceTypeIdentifier>
            <tsl:ServiceName><tsl:Name xml:lang="en">Rakvor Lab TSA (synthetic QTST service)</tsl:Name></tsl:ServiceName>
            <tsl:ServiceDigitalIdentity><tsl:DigitalId><tsl:X509Certificate>$TSA</tsl:X509Certificate></tsl:DigitalId></tsl:ServiceDigitalIdentity>
            <tsl:ServiceStatus>$S/granted</tsl:ServiceStatus>
            <tsl:StatusStartingTime>2025-06-01T00:00:00Z</tsl:StatusStartingTime>
          </tsl:ServiceInformation>
        </tsl:TSPService>
      </tsl:TSPServices>
    </tsl:TrustServiceProvider>
    <tsl:TrustServiceProvider>
      <tsl:TSPInformation><tsl:TSPName><tsl:Name xml:lang="en">Invented Trust Services Ltd &amp; Co</tsl:Name></tsl:TSPName></tsl:TSPInformation>
      <tsl:TSPServices>
        <tsl:TSPService>
          <tsl:ServiceInformation>
            <tsl:ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</tsl:ServiceTypeIdentifier>
            <tsl:ServiceName><tsl:Name xml:lang="en">Invented Qualified CA 1</tsl:Name></tsl:ServiceName>
            <tsl:ServiceDigitalIdentity><tsl:DigitalId><tsl:X509Certificate>$EU</tsl:X509Certificate></tsl:DigitalId></tsl:ServiceDigitalIdentity>
            <tsl:ServiceStatus>$S/granted</tsl:ServiceStatus>
            <tsl:StatusStartingTime>2025-03-01T00:00:00Z</tsl:StatusStartingTime>
          </tsl:ServiceInformation>
        </tsl:TSPService>
      </tsl:TSPServices>
    </tsl:TrustServiceProvider>
  </tsl:TrustServiceProviderList>
</tsl:TrustServiceStatusList>
XML
{
  echo "ecd_name,service_name,service_type,status,status_from,status_until,certificate_pem_or_b64,source_url,checked_utc"
  echo "Rakvor Lab ECD (sintética),Rakvor Lab Root CA,CA/QC,accredited,2025-01-01T00:00:00Z,2026-07-01T00:00:00Z,$ROOT,https://onac.example.invalid/ecd/rakvor-lab,2026-11-01T00:00:00Z"
  echo "Rakvor Lab ECD (sintética),Rakvor Lab Root CA,CA/QC,suspended,2026-07-01T00:00:00Z,2026-08-01T00:00:00Z,,https://onac.example.invalid/ecd/rakvor-lab,2026-11-01T00:00:00Z"
  echo "Rakvor Lab ECD (sintética),Rakvor Lab Root CA,CA/QC,accredited,2026-08-01T00:00:00Z,,,https://onac.example.invalid/ecd/rakvor-lab,2026-11-01T00:00:00Z"
  printf '"Ejemplo ECD Inventada S.A.S.","Ejemplo CA Firma Digital, Clase 2",CA/QC,accredited,2025-02-01,,"'
  cat invented-ecd-co.crt | tr -d '\r'
  printf '",https://onac.example.invalid/ecd/ejemplo,2026-10-15T09:30:00Z\n'
} > co-sample.csv
echo "trust-list fixtures written to $here"
