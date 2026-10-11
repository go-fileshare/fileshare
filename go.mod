// One binary that serves a disk image over four protocols.
//
// It depends on RELEASED versions of the libraries it uses and carries no
// replace directive: `go install github.com/go-fileshare/fileshare@latest`
// must work, and a replace makes Go refuse it outright -- which is how the
// same command inside go-filesystems/smb was broken for as long as it existed.
module github.com/go-fileshare/fileshare

go 1.27.2

require (
	connectrpc.com/connect/v2 v2.0.0
	github.com/cloudsoda/go-smb2 v0.0.0-20260918041005-0c5d69b69701
	github.com/go-authn/directory v0.11.2
	github.com/go-authn/krb5 v0.3.0
	github.com/go-authn/krl v0.6.0
	github.com/go-authn/oidc v0.4.0
	github.com/go-authn/revocation v0.6.2
	github.com/go-authn/servercert v0.5.1
	github.com/go-authn/sshcert v0.1.5
	github.com/go-filesystems/apfs v0.3.0
	github.com/go-filesystems/btrfs v0.3.0
	github.com/go-filesystems/detect v0.3.0
	github.com/go-filesystems/exfat v0.4.0
	github.com/go-filesystems/ext4 v0.3.0
	github.com/go-filesystems/fat32 v0.5.0
	github.com/go-filesystems/hfsplus v0.4.0
	github.com/go-filesystems/interface v0.5.0
	github.com/go-filesystems/iso9660 v0.4.0
	github.com/go-filesystems/nfs v0.8.1
	github.com/go-filesystems/ntfs v0.2.0
	github.com/go-filesystems/osfs v0.3.0
	github.com/go-filesystems/s3 v0.5.0
	github.com/go-filesystems/sftp v0.7.0
	github.com/go-filesystems/smb v0.7.0
	github.com/go-filesystems/squashfs v0.4.0
	github.com/go-filesystems/ufs v0.3.0
	github.com/go-filesystems/webdav v0.5.0
	github.com/go-filesystems/xfs v0.3.0
	github.com/go-filesystems/zfs v0.3.0
	github.com/go-fsctl/btrfs v0.1.1
	github.com/go-fsctl/projquota v0.1.0
	github.com/go-fsctl/zfs v0.1.1
	github.com/go-jose/go-jose/v4 v4.1.5
	github.com/go-net-health/endpoint v0.1.0
	github.com/go-sql-driver/mysql v1.10.1
	github.com/go-volumes/gpt v0.3.0
	github.com/go-volumes/s3 v0.0.0-20261008064343-cae8ea902cba
	github.com/grpc-transports/control v0.1.1
	github.com/hashicorp/hcl/v2 v2.25.0
	github.com/hiddeco/sshsig v0.2.0
	github.com/hstern/go-ssf v0.1.2-0.20260809201236-e03a65c1fba0
	github.com/jackc/pgx/v5 v5.11.0
	github.com/jcmturner/gokrb5/v8 v8.4.4
	github.com/lestrrat-go/jwx/v3 v3.3.0
	github.com/openpubkey/openpubkey v0.29.0
	github.com/pkg/sftp v1.13.11
	github.com/spf13/cobra v1.10.2
	github.com/spf13/pflag v1.0.10
	golang.org/x/crypto v0.58.0
	golang.org/x/oauth2 v0.37.0
	golang.org/x/sys v0.49.0
	google.golang.org/grpc v1.84.0
	google.golang.org/protobuf v1.36.12
	modernc.org/sqlite v1.60.1
)

require (
	filippo.io/bigmod v0.1.0 // indirect
	filippo.io/edwards25519 v1.2.0 // indirect
	github.com/Azure/go-ntlmssp v0.1.1 // indirect
	github.com/agext/levenshtein v1.2.1 // indirect
	github.com/anchore/go-lzo v0.1.1 // indirect
	github.com/apparentlymart/go-textseg/v15 v15.0.0 // indirect
	github.com/apparentlymart/go-textseg/v17 v17.0.1 // indirect
	github.com/awnumar/memcall v0.1.2 // indirect
	github.com/awnumar/memguard v0.22.3 // indirect
	github.com/bits-and-blooms/bitset v1.24.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/cloudsoda/sddl v0.0.0-20250224235906-926454e91efc // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.1 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/geoffgarside/ber v1.1.0 // indirect
	github.com/glauth/ldap v0.0.0-20260718202943-34c5f9b3cbf1 // indirect
	github.com/go-asn1-ber/asn1-ber v1.5.8 // indirect
	github.com/go-compressions/lzfse v0.4.1 // indirect
	github.com/go-encryptions/ccm v0.0.0-20260927083542-1713f748107c // indirect
	github.com/go-encryptions/xts v0.0.0-20260911133109-312298263872 // indirect
	github.com/go-encryptions/zfscrypt v0.0.0-20260927173133-ff7dd33bb415 // indirect
	github.com/go-fde/apfs v0.0.0-20260912170739-6acb57fc9eb0 // indirect
	github.com/go-filesystems/hostcopy v0.1.0 // indirect
	github.com/go-ldap/ldap/v3 v3.4.15 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-volumes/safeio v0.0.0-20260831125406-d8f54b2890d4 // indirect
	github.com/goccy/go-json v0.10.6 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/gorilla/securecookie v1.1.2 // indirect
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	github.com/hstern/go-subjectid v0.0.0-20260525222327-b47140763585 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/jcmturner/aescts/v2 v2.0.0 // indirect
	github.com/jcmturner/dnsutils/v2 v2.0.0 // indirect
	github.com/jcmturner/gofork v1.7.6 // indirect
	github.com/jcmturner/goidentity/v6 v6.0.1 // indirect
	github.com/jcmturner/rpc/v2 v2.0.3 // indirect
	github.com/klauspost/compress v1.20.1 // indirect
	github.com/kr/fs v0.1.0 // indirect
	github.com/lestrrat-go/blackmagic v1.0.4 // indirect
	github.com/lestrrat-go/dsig v1.4.0 // indirect
	github.com/lestrrat-go/dsig-secp256k1 v1.0.0 // indirect
	github.com/lestrrat-go/httpcc v1.0.1 // indirect
	github.com/lestrrat-go/httprc/v3 v3.0.6 // indirect
	github.com/lestrrat-go/option/v2 v2.0.0 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/mitchellh/go-wordwrap v1.0.1 // indirect
	github.com/muhlemmer/gu v0.3.1 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/pierrec/lz4/v4 v4.1.33 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/segmentio/asm v1.2.1 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	github.com/stretchr/testify v1.12.1 // indirect
	github.com/ulikunitz/xz v0.5.17 // indirect
	github.com/valyala/fastjson v1.6.10 // indirect
	github.com/yeqown/go-qrcode/v2 v2.2.5 // indirect
	github.com/yeqown/reedsolomon v1.0.0 // indirect
	github.com/zclconf/go-cty v1.19.0 // indirect
	github.com/zitadel/logging v0.6.0 // indirect
	github.com/zitadel/oidc/v3 v3.23.2 // indirect
	github.com/zitadel/schema v1.3.0 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/otel v1.44.0 // indirect
	go.opentelemetry.io/otel/metric v1.44.0 // indirect
	go.opentelemetry.io/otel/trace v1.44.0 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/exp v0.0.0-20231006140011-7918f672742d // indirect
	golang.org/x/mod v0.41.0 // indirect
	golang.org/x/net v0.60.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/text v0.43.0 // indirect
	golang.org/x/tools v0.51.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260706201446-f0a921348800 // indirect
	modernc.org/libc v1.77.1 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.12.1 // indirect
)
