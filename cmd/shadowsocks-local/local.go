package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"path"
	"strconv"
	"strings"
	"syscall"
	"time"

	ss "github.com/shadowsocks-go/shadowsocks"
)

var debug ss.DebugLog

var (
	errAddrType      = errors.New("socks addr type not supported")
	errVer           = errors.New("socks version not supported")
	errMethod        = errors.New("socks only support 1 method now")
	errAuthExtraData = errors.New("socks authentication get extra data")
	errReqExtraData  = errors.New("socks request get extra data")
	errCmd           = errors.New("socks command not supported")
)

const (
	socksVer5       = 5
	socksCmdConnect = 1
	socksCmdUDP     = 3
)

func init() {
	rand.Seed(time.Now().Unix())
}

func handShake(conn net.Conn) (err error) {
	const (
		idVer     = 0
		idNmethod = 1
	)
	// version identification and method selection message in theory can have
	// at most 256 methods, plus version and nmethod field in total 258 bytes
	// the current rfc defines only 3 authentication methods (plus 2 reserved),
	// so it won't be such long in practice

	buf := make([]byte, 258)
	// 1.VER		版本号 0x5
	// 2.NMETHODS	METHODS字段中出现的方法标示的数目 0x1
	// 3.METHODS	验证方法 0x0=不验证 0x2=用户/密码
	// 0x05 0x01 0x00 则表示客户端只支持一种（0x1）认证方法0x00 （无验证需求）
	// 0x05 0x01 0x02 则表示客户端只支持一种（0x01）认证方法0x02（用户名/密码 验证）
	// 0x05 0x02 0x00 0x02 则表示客户端支持两种(0x02)认证方法“0x00与0x02”
	var n int
	ss.SetReadTimeout(conn)
	// make sure we get the nmethod field
	// 读取两个字节
	if n, err = io.ReadAtLeast(conn, buf, idNmethod+1); err != nil {
		return
	}

	// 测试输出收到数据
	log.Println("handShake : ", buf[0], buf[1], buf[2])

	// 判断socks5版本 必须等于 5
	if buf[idVer] != socksVer5 {
		return errVer
	}
	// 判断方法
	nmethod := int(buf[idNmethod])
	msgLen := nmethod + 2
	if n == msgLen { // handshake done, common case
		// do nothing, jump directly to send confirmation
	} else if n < msgLen { // has more methods to read, rare case
		if _, err = io.ReadFull(conn, buf[n:msgLen]); err != nil {
			return
		}
	} else { // error, should not get extra data
		return errAuthExtraData
	}
	// send confirmation: version 5, no authentication required
	// 1.VER 版本号 0x5
	// 2.METHOD 验证方法 0x0=不验证 0x2=用户/密码
	// 返回给client
	// 发送socks5,0 表示不需要验证
	_, err = conn.Write([]byte{socksVer5, 0})
	return
}

func getRequest(conn net.Conn) (rawaddr []byte, host string, err error) {
	const (
		idVer   = 0
		idCmd   = 1
		idRsv   = 2
		idType  = 3 // address type index
		idIP0   = 4 // ip addres start index
		idDmLen = 4 // domain address length index
		idDm0   = 5 // domain address start index

		typeIPv4 = 1 // type is ipv4 address
		typeDm   = 3 // type is domain address
		typeIPv6 = 4 // type is ipv6 address

		lenIPv4   = 3 + 1 + net.IPv4len + 2 // 3(ver+cmd+rsv) + 1addrType + ipv4 + 2port
		lenIPv6   = 3 + 1 + net.IPv6len + 2 // 3(ver+cmd+rsv) + 1addrType + ipv6 + 2port
		lenDmBase = 3 + 1 + 1 + 2           // 3 + 1addrType + 1addrLen + 2port, plus addrLen
	)

	/*
		1.VER 协议版本 0x5
		2.CMD 连接请求 · 1=CONNECT 2=BIND 3=UDP
		3.RSV 保留字段 0x0
		4.ATYP 地址类型 1=IPV4 3=域名 4=IPV6
		5.DST.ADDR 目的地址 4字节 长度不定
		6.DST.PORT 端口号 2个字节
	*/

	// refer to getRequest in server.go for why set buffer size to 263
	buf := make([]byte, 263)

	var n int
	ss.SetReadTimeout(conn)

	// read till we get possible domain length field
	if n, err = io.ReadAtLeast(conn, buf, idDmLen+1); err != nil {
		return
	}

	//log.Println("getRequest ", buf)

	log.Println("getRequest ", buf[idVer], buf[idCmd], buf[idRsv], buf[idType])
	// check version and cmd
	// 判断socks5版本号
	if buf[idVer] != socksVer5 {
		err = errVer
		return
	}
	// 判断连接请求，这暂时只支持tcp connect
	if buf[idCmd] != socksCmdConnect {
		err = errCmd
		return
	}

	reqLen := -1
	switch buf[idType] {
	case typeIPv4:
		reqLen = lenIPv4
	case typeIPv6:
		reqLen = lenIPv6
	case typeDm:
		reqLen = int(buf[idDmLen]) + lenDmBase
	default:
		err = errAddrType
		return
	}

	if n == reqLen {
		// common case, do nothing
	} else if n < reqLen { // rare case
		if _, err = io.ReadFull(conn, buf[n:reqLen]); err != nil {
			return
		}
	} else {
		err = errReqExtraData
		return
	}

	rawaddr = buf[idType:reqLen]

	if debug {
		switch buf[idType] {
		case typeIPv4:
			host = net.IP(buf[idIP0 : idIP0+net.IPv4len]).String()
		case typeIPv6:
			host = net.IP(buf[idIP0 : idIP0+net.IPv6len]).String()
		case typeDm:
			host = string(buf[idDm0 : idDm0+buf[idDmLen]])
		}
		port := binary.BigEndian.Uint16(buf[reqLen-2 : reqLen])
		host = net.JoinHostPort(host, strconv.Itoa(int(port)))
	}

	return
}

type ServerCipher struct {
	server string
	cipher *ss.Cipher
}

var servers struct {
	srvCipher []*ServerCipher
	failCnt   []int // failed connection count
}

func parseServerConfig(config *ss.Config) {
	hasPort := func(s string) bool {
		_, port, err := net.SplitHostPort(s)
		if err != nil {
			return false
		}
		return port != ""
	}

	if len(config.ServerPassword) == 0 {
		method := config.Method
		if config.Auth {
			method += "-auth"
		}
		// only one encryption table
		cipher, err := ss.NewCipher(method, config.Password)
		if err != nil {
			log.Fatal("Failed generating ciphers:", err)
		}

		srvPort := strconv.Itoa(config.ServerPort)
		srvArr := config.GetServerArray()
		n := len(srvArr)
		servers.srvCipher = make([]*ServerCipher, n)

		for i, s := range srvArr {
			if hasPort(s) {
				log.Println("ignore server_port option for server", s)
				servers.srvCipher[i] = &ServerCipher{s, cipher}
			} else {
				servers.srvCipher[i] = &ServerCipher{net.JoinHostPort(s, srvPort), cipher}
			}
		}
	} else {
		// multiple servers
		n := len(config.ServerPassword)
		servers.srvCipher = make([]*ServerCipher, n)

		cipherCache := make(map[string]*ss.Cipher)
		i := 0
		for _, serverInfo := range config.ServerPassword {
			if len(serverInfo) < 2 || len(serverInfo) > 3 {
				log.Fatalf("server %v syntax error\n", serverInfo)
			}
			server := serverInfo[0]
			passwd := serverInfo[1]
			encmethod := ""
			if len(serverInfo) == 3 {
				encmethod = serverInfo[2]
			}
			if !hasPort(server) {
				log.Fatalf("no port for server %s\n", server)
			}
			// Using "|" as delimiter is safe here, since no encryption
			// method contains it in the name.
			cacheKey := encmethod + "|" + passwd
			cipher, ok := cipherCache[cacheKey]
			if !ok {
				var err error
				cipher, err = ss.NewCipher(encmethod, passwd)
				if err != nil {
					log.Fatal("Failed generating ciphers:", err)
				}
				cipherCache[cacheKey] = cipher
			}
			servers.srvCipher[i] = &ServerCipher{server, cipher}
			i++
		}
	}
	servers.failCnt = make([]int, len(servers.srvCipher))
	for _, se := range servers.srvCipher {
		log.Println("available remote server", se.server)
	}
	return
}

func connectToServer(serverId int, rawaddr []byte, addr string) (remote *ss.Conn, err error) {
	se := servers.srvCipher[serverId]
	remote, err = ss.DialWithRawAddr(rawaddr, se.server, se.cipher.Copy())
	if err != nil {
		log.Println("error connecting to shadowsocks server:", err)
		const maxFailCnt = 30
		if servers.failCnt[serverId] < maxFailCnt {
			servers.failCnt[serverId]++
		}
		return nil, err
	}
	debug.Printf("connected to %s via %s\n", addr, se.server)
	servers.failCnt[serverId] = 0
	return
}

// Connection to the server in the order specified in the config. On
// connection failure, try the next server. A failed server will be tried with
// some probability according to its fail count, so we can discover recovered
// servers.
func createServerConn(rawaddr []byte, addr string) (remote *ss.Conn, err error) {
	const baseFailCnt = 20
	n := len(servers.srvCipher)
	skipped := make([]int, 0)
	for i := 0; i < n; i++ {
		// skip failed server, but try it with some probability
		if servers.failCnt[i] > 0 && rand.Intn(servers.failCnt[i]+baseFailCnt) != 0 {
			skipped = append(skipped, i)
			continue
		}
		remote, err = connectToServer(i, rawaddr, addr)
		if err == nil {
			return
		}
	}
	// last resort, try skipped servers, not likely to succeed
	for _, i := range skipped {
		remote, err = connectToServer(i, rawaddr, addr)
		if err == nil {
			return
		}
	}
	return nil, err
}

func handleConnection(conn net.Conn) {
	if debug {
		debug.Printf("socks connect from %s\n", conn.RemoteAddr().String())
	}
	closed := false
	// 函数运行结束后关闭conn
	defer func() {
		if !closed {
			conn.Close()
		}
	}()

	// socks5 握手
	var err error = nil
	if err = handShake(conn); err != nil {
		log.Println("socks handshake:", err)
		return
	}

	// 建立连接
	//rawaddr, addr, err := getRequest(conn)
	_, addr, err := getRequest(conn)
	if err != nil {
		log.Println("error getting request:", err)
		return
	}

	// Sending connection established message immediately to client.
	// This some round trip time for creating socks connection with the client.
	// But if connection failed, the client will get connection reset error.
	// 发送给client数据
	_, err = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x08, 0x43})
	if err != nil {
		debug.Println("send connection confirmation:", err)
		return
	}

	//log.Println("handleConnection is run. %s", rawaddr, addr)
	//return
	/*
		// 连接server服务端
		remote, err := createServerConn(rawaddr, addr)
		if err != nil {
			if len(servers.srvCipher) > 1 {
				log.Println("Failed connect to all avaiable shadowsocks server")
			}
			return
		}
		defer func() {
			if !closed {
				remote.Close()
			}
		}()
	*/

	// 连接目标服务器端口
	remote, err := net.Dial("tcp", addr)
	if err != nil {
		log.Println("handleConnection 创建remote失败", err)
		return
	}
	defer func() {
		if !closed {
			remote.Close()
		}
	}()

	// 接收数据
	go ss.PipeThenClose(conn, remote)
	// 发送数据到client
	ss.PipeThenClose(remote, conn)

	closed = true
	debug.Println("closed connection to", addr)
}

// tcp 函数
func run(listenAddr string) {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("starting local socks5 server at %v ...\n", listenAddr)
	for {
		// 等待连接
		conn, err := ln.Accept()
		if err != nil {
			log.Println("accept:", err)
			continue
		}
		go handleConnection(conn)
	}
}

/*
func handleConnectionUDP(conn *net.UDPConn, n int, remoteAddr net.Addr, buf []byte) {
	// 解析远程IP和端口
	rIP := buf[4:8]
	rPort := buf[8:10]
	data := buf[10:]
	log.Println("handleConnectionUDP ", remoteAddr, rIP, rPort)

	strIP := string(rIP)
	strPort := string(rPort)

	rAddr, err := net.ResolveUDPAddr("udp", strIP+":"+strPort)
	if err != nil {
		log.Println("handleConnectionUDP Can't resolve address: ", err)
		return
	}
	connClient, err := net.DialUDP("udp", nil, rAddr)
	if err != nil {
		log.Printf("handleConnectionUDP error DialUDP %v\n", err)
		return
	}
	log.Println("handleConnectionUDP is run")
	return
	// 发送数据到目标服务器
	_, err = connClient.WriteTo(data, rAddr)
	if err != nil {
		log.Printf("handleConnectionUDP error WriteTo %v\n", err)
		return
	}
	log.Println("handleConnectionUDP is run")
	return

	// 接收数据
	readbuf := make([]byte, 1024)
	n, remoteAddr, err = connClient.ReadFromUDP(readbuf[0:])
	if err != nil {
		log.Println("handleConnectionUDP ReadFromUDP error", err)
		return
	}
	// 发送给来的端口
	_, err = connClient.WriteTo(readbuf[0:], remoteAddr)
	if err != nil {
		log.Printf("handleConnectionUDP error WriteTo->Client %v\n", err)
		return
	}
}

func handleRequestUDP(conn *net.UDPConn) error {
	buf := make([]byte, 1024)
	n, remoteAddr, err := conn.ReadFromUDP(buf[0:])
	if err != nil {
		log.Println("handleRequestUDP ReadFromUDP error", err)
		return err
	}
	go handleConnectionUDP(conn, n, remoteAddr, buf)
	return nil
}

// udp 函数
func runUDP(listenAddr string) {
	addr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		log.Println("Can't resolve address: ", err)
		return
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Printf("error listening udp %v\n", err)
		return
	}
	log.Printf("starting udp at %v ...\n", listenAddr)
	defer conn.Close()
	for {
		if err := handleRequestUDP(conn); err != nil {
			debug.Println(err)
		}
	}
}
*/

func enoughOptions(config *ss.Config) bool {
	return config.Server != nil && config.ServerPort != 0 &&
		config.LocalPort != 0 && config.Password != ""
}

func main() {
	log.SetOutput(os.Stdout)

	var configFile, cmdServer, cmdLocal string
	var cmdConfig ss.Config
	var printVer bool

	// 启动参数
	flag.BoolVar(&printVer, "version", false, "print version")
	flag.StringVar(&configFile, "c", "config.json", "specify config file")
	flag.StringVar(&cmdServer, "s", "", "server address")
	flag.StringVar(&cmdLocal, "b", "", "local address, listen only to this address if specified")
	flag.StringVar(&cmdConfig.Password, "k", "", "password")
	flag.IntVar(&cmdConfig.ServerPort, "p", 0, "server port")
	flag.IntVar(&cmdConfig.Timeout, "t", 300, "timeout in seconds")
	flag.IntVar(&cmdConfig.LocalPort, "l", 0, "local socks5 proxy port")
	flag.StringVar(&cmdConfig.Method, "m", "", "encryption method, default: aes-256-cfb")
	flag.BoolVar((*bool)(&debug), "d", false, "print debug message")
	flag.BoolVar(&cmdConfig.Auth, "A", false, "one time auth")

	flag.Parse()

	if printVer {
		ss.PrintVersion()
		os.Exit(0)
	}

	cmdConfig.Server = cmdServer
	ss.SetDebug(debug)
	// 判断加密选项是否开启 auth 验证
	if strings.HasSuffix(cmdConfig.Method, "-auth") {
		cmdConfig.Method = cmdConfig.Method[:len(cmdConfig.Method)-5]
		cmdConfig.Auth = true
	}
	// 判断和获取配置文件
	exists, err := ss.IsFileExists(configFile)
	// If no config file in current directory, try search it in the binary directory
	// Note there's no portable way to detect the binary directory.
	binDir := path.Dir(os.Args[0])
	if (!exists || err != nil) && binDir != "" && binDir != "." {
		oldConfig := configFile
		configFile = path.Join(binDir, "config.json")
		log.Printf("%s not found, try config file %s\n", oldConfig, configFile)
	}
	// 解析配置文件
	config, err := ss.ParseConfig(configFile)
	if err != nil {
		config = &cmdConfig
		if !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "error reading %s: %v\n", configFile, err)
			os.Exit(1)
		}
	} else {
		ss.UpdateConfig(config, &cmdConfig)
	}
	// 检测加密方式
	if config.Method == "" {
		config.Method = "aes-256-cfb"
	}
	// 检测服务器密码是否为空
	if len(config.ServerPassword) == 0 {
		if !enoughOptions(config) {
			fmt.Fprintln(os.Stderr, "must specify server address, password and both server/local port")
			os.Exit(1)
		}
	} else {
		if config.Password != "" || config.ServerPort != 0 || config.GetServerArray() != nil {
			fmt.Fprintln(os.Stderr, "given server_password, ignore server, server_port and password option:", config)
		}
		// 检测本地端口
		if config.LocalPort == 0 {
			fmt.Fprintln(os.Stderr, "must specify local port")
			os.Exit(1)
		}
	}
	// 解析服务器配置
	//parseServerConfig(config)

	go run(cmdLocal + ":" + strconv.Itoa(config.LocalPort))
	//go runUDP(cmdLocal + ":" + strconv.Itoa(config.LocalPort))

	waitSignal()
}

func waitSignal() {
	var sigChan = make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGHUP)
	for sig := range sigChan {
		if sig == syscall.SIGHUP {
			//updatePasswd()
		} else {
			// is this going to happen?
			log.Printf("caught signal %v, exit", sig)
			os.Exit(0)
		}
	}
}
