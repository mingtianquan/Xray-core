// Package all includes all commands in Xray.
package all

import (
	// Commands
	"github.com/xtls/xray-core/main/commands/all/api"
	"github.com/xtls/xray-core/main/commands/all/convert"
	"github.com/xtls/xray-core/main/commands/all/httpapi"
	"github.com/xtls/xray-core/main/commands/all/tls"
	"github.com/xtls/xray-core/main/commands/base"
)

func init() {
	base.RootCommand.Commands = append(
		base.RootCommand.Commands,
		api.CmdAPI,
		convert.CmdConvert,
		tls.CmdTLS,
		httpapi.CmdHTTPAPI,
		cmdUUID,
		cmdX25519,
		cmdWG,
	)
}
