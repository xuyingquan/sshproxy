// Copyright 2015, 2016 xyq <yingquan.xu@shatacloud.com>. All rights reserved.
//
// https://github.com/xuyingquan/sshpiper

package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"

	"github.com/tg123/sshpiper/ssh"
	"github.com/tg123/sshpiper/sshpiperd/challenger"
	"github.com/xuyingquan/goini"
)

var (
	logger = log.New(os.Stdout, "", log.Ldate|log.Ltime)
	conf   = goini.NewConfig("/etc/sshpiperd.conf")
)

func showHelpOrVersion() {
	if config.ShowHelp {
		showHelp()
		os.Exit(0)
	}

	if config.ShowVersion {
		os.Exit(0)
	}
}

func main() {

	initConfig()
	initTemplate()
	initLogger()

	showVersion()
	showHelpOrVersion()

	showConfig()

	// 实现FindUpstream和MapPublicKey
	piper := &ssh.SSHPiperConfig{
		FindUpstream: findUpstreamFromRedis,
		MapPublicKey: mapPublicKeyFromRedis,
	}

	if config.Challenger != "" {
		ac, err := challenger.GetChallenger(config.Challenger)
		if err != nil {
			logger.Fatalln("failed to load challenger", err)
		}

		logger.Printf("using additional challenger %s", config.Challenger)
		piper.AdditionalChallenge = ac
	}

	privateBytes, err := ioutil.ReadFile(config.PiperKeyFile)
	if err != nil {
		logger.Fatalln(err)
	}
	//	fmt.Println(string(privateBytes))

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		logger.Fatalln(err)
	}
	//	fmt.Println(private.PublicKey().Marshal())

	piper.AddHostKey(private)

	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", config.ListenAddr, config.Port))
	if err != nil {
		logger.Fatalln("failed to listen for connection: %v", err)
	}
	defer listener.Close()

	logger.Printf("SSHPiperd started")

	for {
		c, err := listener.Accept()
		if err != nil {
			logger.Printf("failed to accept connection: %v", err)
			continue
		}

		logger.Printf("connection accepted: %v", c.RemoteAddr())
		go func() {
			p, err := ssh.NewSSHPiperConn(c, piper)

			if err != nil {
				logger.Printf("connection from %v establishing failed reason: %v", c.RemoteAddr(), err)
				return
			}

			err = p.Wait()
			logger.Printf("connection from %v closed reason: %v", c.RemoteAddr(), err)
		}()
	}
}
