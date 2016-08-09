// Copyright 2014, 2015 tgic<farmer1992@gmail.com>. All rights reserved.
// this file is governed by MIT-license
//
// https://github.com/tg123/sshpiper

package main

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"regexp"
	"strings"

	"github.com/tg123/sshpiper/ssh"
	"menteslibres.net/gosexy/redis"
)

type userFile string

var (
	UserAuthorizedKeysFile userFile = "authorized_keys"
	UserKeyFile            userFile = "id_rsa"
	UserUpstreamFile       userFile = "sshpiper_upstream"

	usernameRule *regexp.Regexp
)

var (
	HOST = "127.0.0.1"
	PORT = uint(6379)
)

func init() {
	// http://stackoverflow.com/questions/6949667/what-are-the-real-rules-for-linux-usernames-on-centos-6-and-rhel-6
	// #NAME_REGEX="^[a-z][-a-z0-9_]*\$"
	usernameRule, _ = regexp.Compile("^[a-z_][a-z0-9_]{0,30}$")
}

func userSpecFile(user, file string) string {
	return fmt.Sprintf("%s/%s/%s", config.WorkingDir, user, file)
}

func (file userFile) read(user string) ([]byte, error) {
	return ioutil.ReadFile(userSpecFile(user, string(file)))
}

func (file userFile) realPath(user string) string {
	return userSpecFile(user, string(file))
}

// return error if other and group have access right
func (file userFile) checkPerm(user string) error {
	filename := userSpecFile(user, string(file))
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return err
	}

	if fi.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("%v's perm is too open", filename)
	}

	return nil
}

// return false if username is not a valid unix user name
// this is for security reason
func checkUsername(user string) bool {
	if config.AllowBadUsername {
		return true
	}

	return usernameRule.MatchString(user)
}

func parseUpstreamFile(data string) (string, string) {

	var user string
	var line string

	r := bufio.NewReader(strings.NewReader(data))

	for {
		var err error
		line, err = r.ReadString('\n')
		if err != nil {
			break
		}

		line = strings.TrimSpace(line)

		if line != "" && line[0] != '#' {
			break
		}
	}

	t := strings.SplitN(line, "@", 2)

	if len(t) > 1 {
		user = t[0]
		line = t[1]
	}

	// test if ok
	if _, _, err := net.SplitHostPort(line); err != nil && line != "" {
		// test valid after concat :22
		if _, _, err := net.SplitHostPort(line + ":22"); err == nil {
			line += ":22"
		}
	}

	return line, user
}

func findUpstreamFromUserfile(conn ssh.ConnMetadata) (net.Conn, string, error) {
	user := conn.User()

	if !checkUsername(user) {
		return nil, "", fmt.Errorf("downstream is not using a valid username")
	}

	err := UserUpstreamFile.checkPerm(user)
	if err != nil {
		return nil, "", err
	}

	data, err := UserUpstreamFile.read(user)
	if err != nil {
		return nil, "", err
	}

	addr, mappedUser := parseUpstreamFile(string(data))

	if addr == "" {
		return nil, "", fmt.Errorf("empty addr")
	}

	logger.Printf("mapping user [%v] to [%v@%v]", user, mappedUser, addr)

	c, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, "", err
	}

	return c, mappedUser, nil
}

func mapPublicKeyFromUserfile(conn ssh.ConnMetadata, key ssh.PublicKey) (signer ssh.Signer, err error) {
	user := conn.User()

	if !checkUsername(user) {
		return nil, fmt.Errorf("downstream is not using a valid username")
	}

	defer func() { // print error when func exit
		if err != nil {
			logger.Printf("mapping private key error: %v, public key auth denied for [%v] from [%v]", err, user, conn.RemoteAddr())
		}
	}()

	err = UserAuthorizedKeysFile.checkPerm(user)
	if err != nil {
		return nil, err
	}

	keydata := key.Marshal()

	var rest []byte
	rest, err = UserAuthorizedKeysFile.read(user)
	if err != nil {
		return nil, err
	}

	var authedPubkey ssh.PublicKey

	for len(rest) > 0 {
		authedPubkey, _, _, rest, err = ssh.ParseAuthorizedKey(rest)

		if err != nil {
			return nil, err
		}

		if bytes.Equal(authedPubkey.Marshal(), keydata) {
			err = UserKeyFile.checkPerm(user)
			if err != nil {
				return nil, err
			}

			var privateBytes []byte
			privateBytes, err = UserKeyFile.read(user)
			if err != nil {
				return nil, err
			}

			var private ssh.Signer
			private, err = ssh.ParsePrivateKey(privateBytes)
			if err != nil {
				return nil, err
			}

			// in log may see this twice, one is for query the other is real sign again
			logger.Printf("auth succ, using mapped private key [%v] for user [%v] from [%v]", UserKeyFile.realPath(user), user, conn.RemoteAddr())
			return private, nil
		}
	}

	logger.Printf("public key auth failed user [%v] from [%v]", conn.User(), conn.RemoteAddr())

	return nil, nil
}

func findUpstreamFromRedis(conn ssh.ConnMetadata) (net.Conn, string, error) {
	user := conn.User()

	if !checkUsername(user) {
		return nil, "", fmt.Errorf("downstream is not using a valid username")
	}

	// 从redis中取出用户IP
	client := redis.New()
	if err := client.Connect(HOST, PORT); err != nil {
		logger.Printf("connect redis server %s:%d failed.", HOST, PORT)
		return nil, "", err
	}
	defer client.Quit()

	userPrefix := "SSH_"
	var buf bytes.Buffer
	buf.WriteString(userPrefix)
	buf.WriteString(user)

	redisUser := buf.String()
	addr, _ := client.Get(redisUser)

	if addr == "" {
		return nil, "", fmt.Errorf("empty addr")
	}

	logger.Printf("mapping user [%v] to [%v@%v]", user, user, addr)

	c, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, "", err
	}

	return c, user, nil
}

func mapPublicKeyFromRedis(conn ssh.ConnMetadata, key ssh.PublicKey) (signer ssh.Signer, err error) {
	user := conn.User()

	if !checkUsername(user) {
		return nil, fmt.Errorf("downstream is not using a valid username")
	}

	defer func() { // print error when func exit
		if err != nil {
			logger.Printf("mapping private key error: %v, public key auth denied for [%v] from [%v]", err, user, conn.RemoteAddr())
		}
	}()

	// 截取用户的publickey（编码后）,从redis中找到对应的公私钥对进行下一步认证
	downKeyBytes := ssh.MarshalAuthorizedKey(key)
	i := bytes.IndexAny(downKeyBytes, " \t")
	if i == -1 {
		logger.Printf("can't parse publickey.")
		return nil, nil
	}
	downKeyBytes = bytes.TrimSpace(downKeyBytes[i+1:])
	//	logger.Printf("publickey length: %d, key: %s", len(downKeyBytes), string(downKeyBytes))

	// 对用户的publickey做MD5码
	h := md5.New()
	h.Write(downKeyBytes)
	downKeyMD5 := fmt.Sprintf("%x", h.Sum(nil))
	//	logger.Printf("md5: %s\n", downKeyMD5)

	// 从redis中取出公私钥对
	client := redis.New()
	if err := client.Connect(HOST, PORT); err != nil {
		logger.Printf("connect redis server %s:%d failed.", HOST, PORT)
		return nil, err
	}
	defer client.Quit()

	redisKey := ""
	redisKey += "KEY_"
	redisKey += user
	mapPrivateKey, err := client.HGet(redisKey, downKeyMD5)
	if err != nil {
		logger.Printf("get private key from redis \"%s\":\"%s\" failure", redisKey, downKeyMD5)
		return nil, err
	}

	var private ssh.Signer
	private, err = ssh.ParsePrivateKey([]byte(mapPrivateKey))
	if err != nil {
		return nil, err
	}

	// in log may see this twice, one is for query the other is real sign again
	logger.Printf("auth success, for user [%v] from [%v]", user, conn.RemoteAddr())
	return private, nil
}
