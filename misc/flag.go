package misc

import (
	"github.com/urfave/cli"
)

// PolyConfigFlag ...
var PolyConfigFlag = cli.StringFlag{
	Name:     "poly-cfg",
	Usage:    "specify poly config file",
	Required: true,
}

// HeightFlag ...
var HeightFlag = cli.IntFlag{
	Name:     "height",
	Usage:    "specify height",
	Required: true,
}

// NodeRPCFlag ...
var NodeRPCFlag = cli.StringFlag{
	Name:     "node_rpc",
	Usage:    "specify node rpc addr",
	Required: true,
}

// NodeRPCsFlag ...
var NodeRPCsFlag = cli.StringFlag{
	Name:     "node_rpcs",
	Usage:    "specify multiple node rpc addr, separate by ,",
	Required: true,
}

// TxFlag ...
var TxFlag = cli.StringFlag{
	Name:     "tx",
	Usage:    "specify poly tx hash",
	Required: true,
}
