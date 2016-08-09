// Copyright 2014, 2015 xyq<yingquan.xu@shatacloud.com>. All rights reserved.
// this file is governed by MIT-license
//
// https://github.com/xuyingquan/sshpiper

package main

import (
	"fmt"
	"log"
	"os"
	"runtime"
	"text/template"
)

var version = "1.0"
var githash = "0000000000"

var (
	config = struct {
		ListenAddr       string
		Port             uint
		WorkingDir       string
		PiperKeyFile     string
		ShowHelp         bool
		Challenger       string
		Logfile          string
		ShowVersion      bool
		AllowBadUsername bool
		RedisHost        string
		RedisPort        uint
	}{}

	out = os.Stdout

	configTemplate  *template.Template
	versionTemplate *template.Template
)

func initTemplate() {
	configTemplate = template.Must(template.New("config").Parse(`
Listening             : {{.ListenAddr}}:{{.Port}}
Server Key File       : {{.PiperKeyFile}}
Working Dir           : {{.WorkingDir}}
Additional Challenger : {{.Challenger}}
Logging file          : {{.Logfile}}

`[1:]))

	versionTemplate = template.Must(template.New("ver").Parse(`
SSHPiper ver: {{.VER}} by xyq <yingquan.xu@shatacloud.com>

go runtime  : {{.GOVER}}
git hash    : {{.GITHASH}}

`[1:]))
}

func initLogger() {
	// change this value for display might be not a good idea
	if config.Logfile != "" {
		f, err := os.OpenFile(config.Logfile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
		if err != nil {
			logger.Printf("cannot open log file %v", err)
			config.Logfile = fmt.Sprintf("stdout, fall back from %v", config.Logfile)
			return
		}

		logger = log.New(f, "", logger.Flags())
	} else {
		config.Logfile = "stdout"
	}
}

func initConfig() {

	config.ListenAddr, _ = conf.GetString("DEFAULT", "LISTEN_ADDR")
	config.Port, _ = conf.GetUint("DEFAULT", "PORT")
	config.WorkingDir, _ = conf.GetString("DEFAULT", "WORKING_DIR")
	config.PiperKeyFile, _ = conf.GetString("DEFAULT", "SERVER_KEY")
	config.Challenger, _ = conf.GetString("DEFAULT", "CHALLENGER")
	config.Logfile, _ = conf.GetString("DEFAULT", "LOG")
	config.AllowBadUsername, _ = conf.GetBool("DEFAULT", "ALLOW_BAD_USER")
	config.ShowHelp, _ = conf.GetBool("DEFAULT", "SHOW_HELP")
	config.ShowVersion, _ = conf.GetBool("DEFAULT", "SHOW_VERSION")
	config.RedisHost, _ = conf.GetString("REDIS", "HOST")
	config.RedisPort, _ = conf.GetUint("REDIS", "PORT")
}

func showHelp() {
	//	mflag.Usage()
}

func showVersion() {
	versionTemplate.Execute(out, struct {
		VER     string
		GOVER   string
		GITHASH string
	}{
		VER:     version,
		GITHASH: githash,
		GOVER:   runtime.Version(),
	})
}

func showConfig() {
	configTemplate.Execute(out, config)
}
