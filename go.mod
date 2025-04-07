module github.com/waygate-io/waygate-go

go 1.24.1

//replace github.com/lastlogin-net/decent-auth-go => ../decent-auth-go
//replace github.com/lastlogin-net/decent-auth-build => ../decent-auth-build

//replace github.com/omnistreams/omnistreams-go => ../omnistreams-go
//replace github.com/omnistreams/omnistreams-go/transports => ../omnistreams-go/transports
//replace github.com/anderspitman/dashtui => ../dashtui
//replace github.com/anderspitman/little-oauth2-go => ../little-oauth2-go
//replace github.com/takingnames/namedrop-libdns => ../namedrop-libdns
//replace github.com/takingnames/namedrop-go => ../namedrop-go
//replace github.com/anderspitman/reanimator-go => ../reanimator-go

//replace github.com/gemdrive/gemdrive-go => ../gemdrive-go

require (
	gioui.org v0.5.0
	github.com/anderspitman/dashtui v0.0.0-20240514182850-c3a359159ce1
	github.com/anderspitman/little-oauth2-go v0.0.0-20241114224916-42fd761b6e86
	github.com/anderspitman/reanimator-go v0.0.0-20250402160345-943313c242a5
	github.com/caddyserver/certmagic v0.22.0
	github.com/jmoiron/sqlx v1.3.5
	github.com/lastlogin-net/decent-auth-go v0.0.0-20250407164606-a45702f72553
	github.com/lestrrat-go/jwx/v2 v2.1.4
	github.com/libdns/libdns v0.2.3
	github.com/libdns/namedotcom v0.3.4-0.20241104014758-c641e4a2a4c9
	github.com/mailgun/proxyproto v1.0.0
	github.com/mdp/qrterminal/v3 v3.2.0
	github.com/omnistreams/omnistreams-go v0.0.0-20250314191905-b56316fba295
	github.com/omnistreams/omnistreams-go/transports v0.0.0-20250314191905-b56316fba295
	github.com/pires/go-proxyproto v0.7.0
	github.com/pkg/browser v0.0.0-20240102092130-5ac0b6a4141c
	github.com/prometheus/client_golang v1.19.0
	github.com/quic-go/quic-go v0.41.0
	github.com/quic-go/webtransport-go v0.6.0
	github.com/takingnames/namedrop-go v0.8.1-0.20250320164145-26a0fc69b8df
	github.com/takingnames/namedrop-libdns v0.0.0-20250320174906-a09f3809efd2
	go.uber.org/zap v1.27.0
	golang.ngrok.com/muxado/v2 v2.0.0
	nhooyr.io/websocket v1.8.10
)

require (
	gioui.org/cpu v0.0.0-20210817075930-8d6a761490d2 // indirect
	gioui.org/shader v1.0.8 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/caddyserver/zerossl v0.1.3 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/coder/websocket v1.8.13 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0 // indirect
	github.com/dylibso/observe-sdk/go v0.0.0-20240819160327-2d926c5d788a // indirect
	github.com/extism/go-sdk v1.6.2-0.20241121002538-bef00f39873e // indirect
	github.com/gdamore/encoding v1.0.1 // indirect
	github.com/gdamore/tcell/v2 v2.8.1 // indirect
	github.com/go-task/slim-sprig/v3 v3.0.0 // indirect
	github.com/go-text/typesetting v0.0.0-20230803102845-24e03d8b5372 // indirect
	github.com/gobwas/glob v0.2.3 // indirect
	github.com/gobwas/httphead v0.1.0 // indirect
	github.com/gobwas/pool v0.2.1 // indirect
	github.com/gobwas/ws v1.4.0 // indirect
	github.com/goccy/go-json v0.10.3 // indirect
	github.com/google/pprof v0.0.0-20241210010833-40e02aabc2ad // indirect
	github.com/ianlancetaylor/demangle v0.0.0-20240805132620-81f5be970eca // indirect
	github.com/klauspost/cpuid/v2 v2.2.10 // indirect
	github.com/lastlogin-net/decent-auth-build v0.0.0-20250404183723-46b2c2f50617 // indirect
	github.com/lestrrat-go/blackmagic v1.0.2 // indirect
	github.com/lestrrat-go/httpcc v1.0.1 // indirect
	github.com/lestrrat-go/httprc v1.0.6 // indirect
	github.com/lestrrat-go/iter v1.0.2 // indirect
	github.com/lestrrat-go/option v1.0.1 // indirect
	github.com/lucasb-eyer/go-colorful v1.2.0 // indirect
	github.com/mattn/go-runewidth v0.0.16 // indirect
	github.com/mattn/go-sqlite3 v1.14.24 // indirect
	github.com/mholt/acmez/v3 v3.1.0 // indirect
	github.com/miekg/dns v1.1.63 // indirect
	github.com/navidys/tvxwidgets v0.10.0 // indirect
	github.com/onsi/ginkgo/v2 v2.22.2 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/prometheus/client_model v0.5.0 // indirect
	github.com/prometheus/common v0.48.0 // indirect
	github.com/prometheus/procfs v0.12.0 // indirect
	github.com/quic-go/qpack v0.4.0 // indirect
	github.com/rivo/tview v0.0.0-20240616192244-23476fa0bab2 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/segmentio/asm v1.2.0 // indirect
	github.com/tetratelabs/wabin v0.0.0-20230304001439-f6f874872834 // indirect
	github.com/tetratelabs/wazero v1.8.1 // indirect
	github.com/zeebo/blake3 v0.2.4 // indirect
	go.opentelemetry.io/proto/otlp v1.3.1 // indirect
	go.uber.org/mock v0.3.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap/exp v0.3.0 // indirect
	golang.org/x/crypto v0.36.0 // indirect
	golang.org/x/exp v0.0.0-20230817173708-d852ddb80c63 // indirect
	golang.org/x/exp/shiny v0.0.0-20220827204233-334a2380cb91 // indirect
	golang.org/x/image v0.11.0 // indirect
	golang.org/x/mod v0.24.0 // indirect
	golang.org/x/net v0.37.0 // indirect
	golang.org/x/oauth2 v0.23.0 // indirect
	golang.org/x/sync v0.12.0 // indirect
	golang.org/x/sys v0.31.0 // indirect
	golang.org/x/term v0.30.0 // indirect
	golang.org/x/text v0.23.0 // indirect
	golang.org/x/tools v0.31.0 // indirect
	google.golang.org/protobuf v1.36.1 // indirect
	rsc.io/qr v0.2.0 // indirect
)
