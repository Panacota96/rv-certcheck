#!/usr/bin/env sh
# Independent certificate fixtures, made with the OpenSSL command line only (no rv-certcheck code), so the tool is
# never graded against its own output. Usage:
#
#   tests/fixtures/make_with_openssl.sh [OUT_DIR]          default OUT_DIR: tests/fixtures/openssl
#   tests/fixtures/make_with_openssl.sh --sample           also refresh examples/sample/{evidence,anchors}
#
# Every certificate is issued with `openssl ca` and fixed -startdate/-enddate, fixed serials, RSA PKCS#1 v1.5
# signatures (deterministic) and the CRL with fixed -crl_lastupdate/-crl_nextupdate and a fixed revocation time,
# so a second run over the same keys gives byte-identical certificates, CSR, bundle, PKCS#7 and CRL.
#
# NOT deterministic (OpenSSL takes the time or randomness itself; no faketime here). These files are written only
# when missing, so re-running the script keeps the committed copies; delete them (or set REGEN_TIME_BOUND=1) to
# make new ones:
#   keys/*.key           key generation is random (the keys are kept and reused: they are test keys only)
#   data.tsr, data.tst   genTime = now, from `openssl ts -reply`
#   leaf-revoked.ocsp    producedAt / thisUpdate = now, from `openssl ocsp -respout`
#   leaf.p12             random salt and IV (password: rakvor-lab)
#
# After the run, openssl-verify.tsv records what `openssl verify` answers for every leaf at the reference time
# (2026-06-01T00:00:00Z) with the lab root as the only anchor and the intermediate CRL: the oracle the analysis
# must agree with. LAB KEYS ONLY: never use these keys or certificates for anything but tests.
set -eu
[ -n "${TRACE:-}" ] && set -x
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
sample=0
out="$here/openssl"
for a in "$@"; do
  case "$a" in
    --sample) sample=1 ;;
    *) out=$a ;;
  esac
done
regen=${REGEN_TIME_BOUND:-0}
mkdir -p "$out/keys"
out=$(cd "$out" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"

# openssl ca reads $ENV::SAN while loading the config (v3_leaf), whatever section is used.
SAN=none.lab.rakvor.test
export SAN

# Reference instant of the set: every validity window is chosen around it.
AT_EPOCH=1780272000 # 2026-06-01T00:00:00Z
AT_ISO=2026-06-01T00:00:00Z

key() { # name bits
  [ -f "$out/keys/$1.key" ] || openssl genpkey -algorithm RSA -pkeyopt "rsa_keygen_bits:$2" -out "$out/keys/$1.key" 2>/dev/null
}

cat > ca.cnf <<'EOF'
[ ca ]
default_ca = lab
[ lab ]
dir = .
database = $dir/index.txt
new_certs_dir = $dir/newcerts
serial = $dir/serial
crlnumber = $dir/crlnumber
default_md = sha256
policy = any
unique_subject = no
copy_extensions = none
email_in_dn = no
[ any ]
countryName = optional
organizationName = optional
organizationalUnitName = optional
commonName = supplied
[ v3_root ]
basicConstraints = critical, CA:true
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
[ v3_int ]
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
crlDistributionPoints = URI:http://pki.lab.rakvor.test/intermediate.crl
[ v3_leaf ]
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
subjectAltName = DNS:$ENV::SAN
crlDistributionPoints = URI:http://pki.lab.rakvor.test/intermediate.crl
authorityInfoAccess = OCSP;URI:http://ocsp.lab.rakvor.test, caIssuers;URI:http://pki.lab.rakvor.test/intermediate.crt
[ v3_tsa ]
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, timeStamping
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
[ tsa ]
default_tsa = lab_tsa
[ lab_tsa ]
signer_digest = sha256
default_policy = 2.25.130074246409705057913773883974790544206.9.2
digests = sha256
accuracy = secs:1
ordering = no
tsa_name = no
ess_cert_id_chain = no
ess_cert_id_alg = sha256
serial = ./tsaserial
EOF

newca() { # dir: an empty CA database
  rm -rf "$1" && mkdir -p "$1/newcerts" && : > "$1/index.txt" && echo 1000 > "$1/crlnumber"
}
issue() { # cadir cacert cakey key subject serial start end ext md out [san]
  echo "$6" > "$1/serial"
  openssl req -new -key "$out/keys/$4.key" -subj "$5" -out "$work/req.csr" 2>/dev/null
  (cd "$1" && SAN="${12:-none.lab.rakvor.test}" openssl ca -batch -config "$work/ca.cnf" -cert "$2" -keyfile "$3" \
    -in "$work/req.csr" -startdate "$7" -enddate "$8" -extensions "$9" -md "${10}" -notext -out "${11}" 2>/dev/null)
}

for k in root intermediate leaf expired notyet revoked other-root wrong-root rsa1024 sha1 mismatch mismatch-other tsa; do
  case $k in rsa1024) key $k 1024 ;; *) key $k 2048 ;; esac
done

# Root (self-signed through `openssl ca -selfsign`, so its dates are fixed too) and intermediate.
newca rootca
echo 01 > rootca/serial
openssl req -new -key "$out/keys/root.key" -subj "/C=CO/O=Rakvor Lab/CN=Rakvor Lab Root CA" -out root.csr
(cd rootca && openssl ca -batch -config "$work/ca.cnf" -selfsign -keyfile "$out/keys/root.key" -in "$work/root.csr" \
  -startdate 20250101000000Z -enddate 20450101000000Z -extensions v3_root -md sha256 -notext -out "$out/root.crt" 2>/dev/null)
issue rootca "$out/root.crt" "$out/keys/root.key" intermediate "/C=CO/O=Rakvor Lab/CN=Rakvor Lab Intermediate CA" \
  1001 20250101000000Z 20400101000000Z v3_int sha256 "$out/intermediate.crt"

# Leaves under the intermediate.
newca intca
I="$out/intermediate.crt"; IK="$out/keys/intermediate.key"
issue intca "$I" "$IK" leaf "/C=CO/O=Rakvor Lab/CN=leaf.lab.rakvor.test" 2001 20260101000000Z 20280101000000Z v3_leaf sha256 "$out/leaf.crt" leaf.lab.rakvor.test
issue intca "$I" "$IK" expired "/C=CO/O=Rakvor Lab/CN=expired.lab.rakvor.test" 2002 20240101000000Z 20250101000000Z v3_leaf sha256 "$out/leaf-expired.crt" expired.lab.rakvor.test
issue intca "$I" "$IK" notyet "/C=CO/O=Rakvor Lab/CN=notyet.lab.rakvor.test" 2003 20300101000000Z 20320101000000Z v3_leaf sha256 "$out/leaf-not-yet-valid.crt" notyet.lab.rakvor.test
issue intca "$I" "$IK" revoked "/C=CO/O=Rakvor Lab/CN=revoked.lab.rakvor.test" 2004 20260101000000Z 20280101000000Z v3_leaf sha256 "$out/leaf-revoked.crt" revoked.lab.rakvor.test
issue intca "$I" "$IK" rsa1024 "/C=CO/O=Rakvor Lab/CN=rsa1024.lab.rakvor.test" 2005 20260101000000Z 20280101000000Z v3_leaf sha256 "$out/leaf-rsa1024.crt" rsa1024.lab.rakvor.test
issue intca "$I" "$IK" sha1 "/C=CO/O=Rakvor Lab/CN=sha1.lab.rakvor.test" 2006 20260101000000Z 20280101000000Z v3_leaf sha1 "$out/leaf-sha1.crt" sha1.lab.rakvor.test
issue intca "$I" "$IK" mismatch "/C=CO/O=Rakvor Lab/CN=mismatch.lab.rakvor.test" 2007 20260101000000Z 20280101000000Z v3_leaf sha256 "$out/leaf-mismatch.crt" mismatch.lab.rakvor.test
issue intca "$I" "$IK" tsa "/C=CO/O=Rakvor Lab/CN=Rakvor Lab TSA" 2008 20250101000000Z 20350101000000Z v3_tsa sha256 "$out/tsa.crt"
# The key shipped with leaf-mismatch.crt is NOT its key (same file stem: they are presented as a pair).
cp "$out/keys/mismatch-other.key" "$out/leaf-mismatch.key"
cp "$out/keys/leaf.key" "$out/leaf.key"

# Revocation: serial 2004 revoked on 2026-02-01 (keyCompromise); CRL issued 2026-03-01, next update 2027-01-01.
(cd intca && openssl ca -batch -config "$work/ca.cnf" -cert "$I" -keyfile "$IK" -revoke "$out/leaf-revoked.crt" -crl_reason keyCompromise 2>/dev/null)
awk 'BEGIN { FS = OFS = "\t" } $4 == "2004" { $1 = "R"; $3 = "260201000000Z,keyCompromise" } { print }' intca/index.txt > intca/index.new
mv intca/index.new intca/index.txt
echo 1000 > intca/crlnumber
(cd intca && openssl ca -batch -config "$work/ca.cnf" -cert "$I" -keyfile "$IK" -gencrl -md sha256 \
  -crl_lastupdate 20260301000000Z -crl_nextupdate 20270101000000Z -out "$work/int.crl.pem" 2>/dev/null)
openssl crl -in int.crl.pem -outform DER -out "$out/intermediate.crl"

# Wrong root: a leaf whose root is not the lab root.
newca otherca
echo 01 > otherca/serial
openssl req -new -key "$out/keys/other-root.key" -subj "/C=CO/O=Unrelated Lab/CN=Unrelated Root CA" -out other.csr
(cd otherca && openssl ca -batch -config "$work/ca.cnf" -selfsign -keyfile "$out/keys/other-root.key" -in "$work/other.csr" \
  -startdate 20250101000000Z -enddate 20450101000000Z -extensions v3_root -md sha256 -notext -out "$out/other-root.crt" 2>/dev/null)
issue otherca "$out/other-root.crt" "$out/keys/other-root.key" wrong-root "/C=CO/O=Unrelated Lab/CN=wrong-root.lab.rakvor.test" \
  3001 20260101000000Z 20280101000000Z v3_leaf sha256 "$out/leaf-wrong-root.crt" wrong-root.lab.rakvor.test

# Containers: PEM bundle, PKCS#7 (no CRL), CSR.
cat "$out/intermediate.crt" "$out/root.crt" > "$out/chain-bundle.pem"
openssl crl2pkcs7 -nocrl -certfile "$out/chain-bundle.pem" -outform DER -out "$out/chain.p7b"
openssl req -new -key "$out/keys/leaf.key" -subj "/C=CO/O=Rakvor Lab/CN=csr.lab.rakvor.test" -out "$out/leaf.csr"

# Time-bound and random outputs: written only when missing (see the header).
printf 'Acta de entrega de evidencia, caso LAB-001.\n' > "$out/data.txt"
if [ "$regen" = 1 ] || [ ! -f "$out/data.tsr" ]; then
  echo 01 > tsaserial
  openssl ts -query -data "$out/data.txt" -sha256 -cert -no_nonce -out data.tsq
  openssl ts -reply -config ca.cnf -section lab_tsa -queryfile data.tsq -signer "$out/tsa.crt" -inkey "$out/keys/tsa.key" \
    -chain "$out/intermediate.crt" -out "$out/data.tsr" 2>/dev/null
  openssl ts -reply -in "$out/data.tsr" -token_out -out "$out/data.tst"
fi
if [ "$regen" = 1 ] || [ ! -f "$out/leaf-revoked.ocsp" ]; then
  openssl ocsp -index intca/index.txt -rsigner "$I" -rkey "$IK" -CA "$I" -issuer "$I" -serial 0x2004 \
    -ndays 30 -respout "$out/leaf-revoked.ocsp" >/dev/null 2>&1
fi
if [ "$regen" = 1 ] || [ ! -f "$out/leaf.p12" ]; then
  openssl pkcs12 -export -inkey "$out/keys/leaf.key" -in "$out/leaf.crt" -certfile "$out/intermediate.crt" \
    -name leaf -passout pass:rakvor-lab -out "$out/leaf.p12"
fi

# Oracle: what `openssl verify` answers at the reference time, lab root as the only anchor, with the CRL.
openssl crl -in "$out/intermediate.crl" -inform DER -out crl.pem
{
  printf 'file\topenssl_verify_code\topenssl_verify_message\n'
  for f in leaf leaf-expired leaf-not-yet-valid leaf-revoked leaf-rsa1024 leaf-sha1 leaf-mismatch leaf-wrong-root tsa; do
    res=$(openssl verify -attime "$AT_EPOCH" -CAfile "$out/root.crt" -untrusted "$out/intermediate.crt" \
      -crl_check -CRLfile crl.pem -show_chain "$out/$f.crt" 2>&1 || true)
    line=$(printf '%s\n' "$res" | grep -E '^error [0-9]+ at' | head -n 1 || true)
    if [ -n "$line" ]; then
      code=$(printf '%s' "$line" | sed -E 's/^error ([0-9]+) at.*/\1/')
      msg=$(printf '%s' "$line" | sed -E 's/^error [0-9]+ at [0-9]+ depth lookup: //')
    else
      code=0; msg=ok
    fi
    printf '%s.crt\t%s\t%s\n' "$f" "$code" "$msg"
  done
} > "$out/openssl-verify.tsv"
printf 'reference_time\t%s\nopenssl\t%s\n' "$AT_ISO" "$(openssl version)" > "$out/oracle-context.tsv"

if [ "$sample" = 1 ]; then
  ev="$repo/examples/sample/evidence"; an="$repo/examples/sample/anchors"
  rm -rf "$ev" && mkdir -p "$ev" "$an"
  cp "$out/root.crt" "$an/rakvor-lab-root.crt"
  for f in intermediate.crt leaf.crt leaf-expired.crt leaf-revoked.crt intermediate.crl leaf-wrong-root.crt \
           leaf-rsa1024.crt leaf-sha1.crt leaf-mismatch.crt leaf-mismatch.key tsa.crt data.txt data.tsr; do
    cp "$out/$f" "$ev/$f"
  done
fi
echo "fixtures written to $out"
