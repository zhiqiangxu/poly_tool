package main

import (
	"fmt"
	"os"
	"runtime"

	"github.com/urfave/cli"
	"github.com/zhiqiangxu/poly_tool/misc"
)

func main() {
	if err := setupAPP().Run(os.Args); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
}

func setupAPP() *cli.App {
	app := cli.NewApp()
	app.Usage = "Poly Tool"
	app.Copyright = "Copyright in 2021"
	app.Commands = []cli.Command{
		misc.PolyCmd,
	}
	app.Flags = []cli.Flag{}
	app.Before = func(context *cli.Context) error {
		runtime.GOMAXPROCS(runtime.NumCPU())
		return nil
	}
	return app
}
