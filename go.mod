module github.com/waygate-io/waygate-go

go 1.22.6

replace github.com/lastlogin-io/obligator => ../obligator

replace github.com/omnistreams/omnistreams-go => ../omnistreams-go

replace github.com/omnistreams/omnistreams-go/transports => ../omnistreams-go/transports

replace github.com/anderspitman/dashtui => ../dashtui

replace github.com/navidys/tvxwidgets => ../tvxwidgets

replace github.com/anderspitman/little-oauth2-go => ../little-oauth2-go

//replace github.com/gemdrive/gemdrive-go => ../gemdrive-go

require (
	gioui.org v0.5.0
	github.com/anderspitman/dashtui v0.0.0-00010101000000-000000000000
	github.com/anderspitman/little-oauth2-go v0.0.0-20240904162115-5d18e06f4a81
	github.com/anderspitman/treemess-go v0.0.0-20210313015619-ba255d9f1e0f
	github.com/caddyserver/certmagic v0.20.0
	github.com/gemdrive/gemdrive-go v0.0.0-20240229172336-f3f7f72ae546
	github.com/jmoiron/sqlx v1.3.5
	github.com/lastlogin-io/obligator v0.0.0-20240320141513-ad56a2786bf7
	github.com/lestrrat-go/jwx/v2 v2.0.11
	github.com/libdns/namedotcom v0.3.3
	github.com/libdns/route53 v1.3.3
	github.com/mailgun/proxyproto v1.0.0
	github.com/mdp/qrterminal/v3 v3.2.0
	github.com/omnistreams/omnistreams-go v0.0.0-00010101000000-000000000000
	github.com/omnistreams/omnistreams-go/transports v0.0.0-00010101000000-000000000000
	github.com/pires/go-proxyproto v0.7.0
	github.com/pkg/browser v0.0.0-20240102092130-5ac0b6a4141c
	github.com/prometheus/client_golang v1.19.0
	github.com/quic-go/quic-go v0.41.0
	github.com/quic-go/webtransport-go v0.6.0
	go.uber.org/zap v1.24.0
	golang.ngrok.com/muxado/v2 v2.0.0
	nhooyr.io/websocket v1.8.10
)

require (
	gioui.org/cpu v0.0.0-20210817075930-8d6a761490d2 // indirect
	gioui.org/shader v1.0.8 // indirect
	github.com/aws/aws-sdk-go-v2 v1.17.8 // indirect
	github.com/aws/aws-sdk-go-v2/config v1.18.21 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.13.20 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.13.2 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.1.32 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.4.26 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.3.33 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.9.26 // indirect
	github.com/aws/aws-sdk-go-v2/service/route53 v1.27.7 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.12.8 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.14.8 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.18.9 // indirect
	github.com/aws/smithy-go v1.13.5 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.2.0 // indirect
	github.com/gdamore/encoding v1.0.0 // indirect
	github.com/gdamore/tcell/v2 v2.7.4 // indirect
	github.com/go-task/slim-sprig v0.0.0-20230315185526-52ccab3ef572 // indirect
	github.com/go-text/typesetting v0.0.0-20230803102845-24e03d8b5372 // indirect
	github.com/gobwas/httphead v0.1.0 // indirect
	github.com/gobwas/pool v0.2.1 // indirect
	github.com/gobwas/ws v1.4.0 // indirect
	github.com/goccy/go-json v0.10.2 // indirect
	github.com/google/pprof v0.0.0-20230821062121-407c9e7a662f // indirect
	github.com/ip2location/ip2location-go/v9 v9.6.0 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/klauspost/cpuid/v2 v2.2.5 // indirect
	github.com/lestrrat-go/blackmagic v1.0.1 // indirect
	github.com/lestrrat-go/httpcc v1.0.1 // indirect
	github.com/lestrrat-go/httprc v1.0.4 // indirect
	github.com/lestrrat-go/iter v1.0.2 // indirect
	github.com/lestrrat-go/option v1.0.1 // indirect
	github.com/libdns/libdns v0.2.1 // indirect
	github.com/lucasb-eyer/go-colorful v1.2.0 // indirect
	github.com/mattn/go-runewidth v0.0.15 // indirect
	github.com/mattn/go-sqlite3 v1.14.18 // indirect
	github.com/mholt/acmez v1.2.0 // indirect
	github.com/miekg/dns v1.1.55 // indirect
	github.com/navidys/tvxwidgets v0.6.0 // indirect
	github.com/nfnt/resize v0.0.0-20180221191011-83c6a9932646 // indirect
	github.com/onsi/ginkgo/v2 v2.17.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/prometheus/client_model v0.5.0 // indirect
	github.com/prometheus/common v0.48.0 // indirect
	github.com/prometheus/procfs v0.12.0 // indirect
	github.com/quic-go/qpack v0.4.0 // indirect
	github.com/rivo/tview v0.0.0-20240501114654-1f4d5e8f881d // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/segmentio/asm v1.2.0 // indirect
	github.com/skip2/go-qrcode v0.0.0-20200617195104-da1b6568686e // indirect
	github.com/zeebo/blake3 v0.2.3 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	go.uber.org/mock v0.3.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/crypto v0.18.0 // indirect
	golang.org/x/exp v0.0.0-20230817173708-d852ddb80c63 // indirect
	golang.org/x/exp/shiny v0.0.0-20220827204233-334a2380cb91 // indirect
	golang.org/x/image v0.11.0 // indirect
	golang.org/x/mod v0.14.0 // indirect
	golang.org/x/net v0.20.0 // indirect
	golang.org/x/sys v0.17.0 // indirect
	golang.org/x/term v0.17.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	golang.org/x/tools v0.17.0 // indirect
	google.golang.org/protobuf v1.32.0 // indirect
	lukechampine.com/uint128 v1.2.0 // indirect
	rsc.io/qr v0.2.0 // indirect
)
