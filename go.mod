module github.com/zhiqiangxu/poly_tool

go 1.15

require (
	github.com/cloudflare/cfssl v1.5.0
	github.com/cosmos/cosmos-sdk v0.39.1
	github.com/ethereum/go-ethereum v1.9.15
	github.com/joeqian10/neo-gogogo v0.0.0-20210118094521-237d985a02d5
	github.com/ontio/ontology v1.12.0
	github.com/ontio/ontology-crypto v1.0.9
	github.com/ontio/ontology-go-sdk v1.11.8
	github.com/polynetwork/bsc-relayer v0.0.0-00010101000000-000000000000
	github.com/polynetwork/eth-contracts v0.0.0-20210115031323-d16252b2b857
	github.com/polynetwork/poly v0.0.0-20210112063446-24e3d053e9d6
	github.com/polynetwork/poly-go-sdk v0.0.0-20210114120411-3dcba035134f
	github.com/urfave/cli v1.22.5
	github.com/zouxyan/eth-contracts v0.0.0-20210115072359-e4cac6edc20c
	google.golang.org/appengine v1.6.7
)

replace github.com/polynetwork/bsc-relayer => github.com/zhiqiangxu/bsc-relayer v0.0.0-20210130014532-be1603259f5a

replace poly-bridge => github.com/polynetwork/poly-bridge v0.0.0-20210126083254-80335b53070a
