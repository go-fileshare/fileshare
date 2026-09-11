// One binary that serves a disk image over four protocols.
//
// It depends on RELEASED versions of the libraries it uses and carries no
// replace directive: `go install github.com/go-fileshare/fileshare@latest`
// must work, and a replace makes Go refuse it outright -- which is how the
// same command inside go-filesystems/smb was broken for as long as it existed.
module github.com/go-fileshare/fileshare

go 1.26.4

require (
	github.com/cloudsoda/go-smb2 v0.0.0-20260803221621-0b399b9d036c
	github.com/go-authn/directory v0.4.0
	github.com/go-authn/oidc v0.1.0
	github.com/go-filesystems/detect v0.1.0
	github.com/go-filesystems/exfat v0.3.1-0.20260909091408-83177cc31aee
	github.com/go-filesystems/ext4 v0.2.1-0.20260909093824-642490429d0a
	github.com/go-filesystems/fat32 v0.3.1-0.20260909090037-17502e127a37
	github.com/go-filesystems/hfsplus v0.2.1-0.20260909093327-1576380a57fd
	github.com/go-filesystems/interface v0.3.0
	github.com/go-filesystems/iso9660 v0.2.1-0.20260909093319-946c297b0c26
	github.com/go-filesystems/nfs v0.2.0
	github.com/go-filesystems/ntfs v0.1.1-0.20260909092247-4afe8a8fc177
	github.com/go-filesystems/sftp v0.3.0
	github.com/go-filesystems/smb v0.2.0
	github.com/go-filesystems/squashfs v0.2.2-0.20260909093323-59fa5d6f474b
	github.com/go-filesystems/webdav v0.1.0
	github.com/go-sql-driver/mysql v1.10.1
	github.com/hashicorp/hcl/v2 v2.24.0
	github.com/jackc/pgx/v5 v5.11.0
	github.com/pkg/sftp v1.13.10
	github.com/spf13/cobra v1.10.2
	github.com/spf13/pflag v1.0.10
	golang.org/x/crypto v0.57.0
	modernc.org/sqlite v1.58.0
)

require (
	filippo.io/edwards25519 v1.2.0 // indirect
	github.com/Azure/go-ntlmssp v0.1.1 // indirect
	github.com/agext/levenshtein v1.2.1 // indirect
	github.com/anchore/go-lzo v0.1.1 // indirect
	github.com/apparentlymart/go-textseg/v15 v15.0.0 // indirect
	github.com/cloudsoda/sddl v0.0.0-20250224235906-926454e91efc // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/geoffgarside/ber v1.1.0 // indirect
	github.com/glauth/ldap v0.0.0-20260718202943-34c5f9b3cbf1 // indirect
	github.com/go-asn1-ber/asn1-ber v1.5.8 // indirect
	github.com/go-compressions/lzfse v0.3.0 // indirect
	github.com/go-encryptions/ccm v0.0.0-20260620055113-74db323be0b2 // indirect
	github.com/go-encryptions/zfscrypt v0.0.0-20260623125925-033c4ad509ed // indirect
	github.com/go-fde/apfs v0.0.0-20260620062418-22bb63627e03 // indirect
	github.com/go-filesystems/apfs v0.1.0 // indirect
	github.com/go-filesystems/btrfs v0.1.0 // indirect
	github.com/go-filesystems/ufs v0.2.0 // indirect
	github.com/go-filesystems/xfs v0.1.0 // indirect
	github.com/go-filesystems/zfs v0.1.0 // indirect
	github.com/go-ldap/ldap/v3 v3.4.14 // indirect
	github.com/go-volumes/gpt v0.0.0-20260831115417-b3069a3ac03a // indirect
	github.com/go-volumes/safeio v0.0.0-20260831125406-d8f54b2890d4 // indirect
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/jcmturner/aescts/v2 v2.0.0 // indirect
	github.com/jcmturner/dnsutils/v2 v2.0.0 // indirect
	github.com/jcmturner/gofork v1.7.6 // indirect
	github.com/jcmturner/goidentity/v6 v6.0.1 // indirect
	github.com/jcmturner/gokrb5/v8 v8.4.4 // indirect
	github.com/jcmturner/rpc/v2 v2.0.3 // indirect
	github.com/klauspost/compress v1.20.0 // indirect
	github.com/kr/fs v0.1.0 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/mitchellh/go-wordwrap v1.0.1 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/pierrec/lz4/v4 v4.1.29 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/ulikunitz/xz v0.5.16 // indirect
	github.com/zclconf/go-cty v1.16.3 // indirect
	golang.org/x/mod v0.41.0 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sync v0.23.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	golang.org/x/tools v0.49.0 // indirect
	modernc.org/libc v1.75.6 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.12.1 // indirect
)
