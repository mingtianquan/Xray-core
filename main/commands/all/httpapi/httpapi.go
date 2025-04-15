package httpapi

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/xtls/xray-core/main/commands/base"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// 一些全局变量
var (
	apiAddr        string
	httpAddr       string
	timeout        int
	saveToConfig   bool
	configPath     string // Xray配置文件路径
	httpConfigPath string // HTTP API配置文件路径
	tempConfigOnly bool
)

// CmdHTTPAPI 启动一个HTTP API服务器来操作Xray
var CmdHTTPAPI = &base.Command{
	UsageLine: "{{.Exec}} httpapi",
	Short:     "Start an HTTP API server for Xray",
	Long: `{{.Exec}} {{.LongName}} starts an HTTP API server to manipulate Xray.
	
Usage:
    {{.Exec}} {{.LongName}} [-api "127.0.0.1:10085"] [-http ":8080"] [-timeout 3] [-save] [-config "config.json"] [-http-config "http-config.json"] [-temp-only]
	
Options:
    -api        Xray API服务器地址 (default: 127.0.0.1:10085)
    -http       HTTP服务器监听地址 (default: :8080)
    -timeout    API调用超时时间（秒）(default: 3)
    -save       同时保存配置到Xray配置文件
    -config     Xray配置文件路径 (default: config.json)
    -http-config HTTP API配置文件路径 (default: [命令行配置名].json)
    -temp-only  只使用临时配置文件，程序结束时删除
`,
}

func init() {
	CmdHTTPAPI.Run = executeHTTPAPI // 设置命令执行函数

	// 定义命令行参数
	CmdHTTPAPI.Flag.StringVar(&apiAddr, "api", "127.0.0.1:10085", "Xray API服务器地址")
	CmdHTTPAPI.Flag.StringVar(&httpAddr, "http", ":8080", "HTTP服务器监听地址")
	CmdHTTPAPI.Flag.IntVar(&timeout, "timeout", 3, "API调用超时时间（秒）")
	CmdHTTPAPI.Flag.BoolVar(&saveToConfig, "save", false, "同时保存配置到Xray配置文件")
	CmdHTTPAPI.Flag.StringVar(&configPath, "config", "config.json", "Xray配置文件路径")
	CmdHTTPAPI.Flag.StringVar(&httpConfigPath, "http-config", "", "HTTP API配置文件路径")
	CmdHTTPAPI.Flag.BoolVar(&tempConfigOnly, "temp-only", false, "只使用临时配置文件，程序结束时删除")
}

// GetConfigFileName 返回当前使用的HTTP API配置文件名
func GetConfigFileName() string {
	// 如果指定了http-config参数，则使用该参数值
	if httpConfigPath != "" {
		return httpConfigPath
	}

	// 如果指定了config参数，则直接使用该参数
	if configPath != "" {
		return configPath
	}

	// 默认情况
	return "xray-http-api.json"
}

// executeHTTPAPI 执行HTTP API服务器命令
func executeHTTPAPI(cmd *base.Command, args []string) {
	// 如果没有指定http-config参数，则设置为基于configPath的值
	if httpConfigPath == "" {
		httpConfigPath = GetConfigFileName()
		log.Printf("未指定HTTP API配置文件，使用默认值: %s", httpConfigPath)
	}

	// 初始化配置
	InitConfig()

	// 如果需要在退出时删除临时配置文件
	if tempConfigOnly {
		defer func() {
			log.Printf("程序退出，删除临时配置文件: %s", httpConfigPath)
			os.Remove(httpConfigPath)
		}()
	}

	log.Printf("Xray HTTP API 服务器启动")
	log.Printf("配置: API服务器=%s, HTTP服务器=%s, 超时=%ds", apiAddr, httpAddr, timeout)
	log.Printf("HTTP API配置文件: %s", httpConfigPath)
	if saveToConfig {
		log.Printf("将同时保存更改到Xray配置文件: %s", configPath)
	}

	// 测试连接到API服务器
	_, _, cleanup, err := ConnectToAPI(apiAddr, timeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "无法连接到API服务器 %s: %v\n", apiAddr, err)
		os.Exit(1)
		return
	}
	cleanup()
	log.Printf("成功连接到API服务器 %s", apiAddr)

	// 注册HTTP处理器
	registerHandlers()

	// 启动HTTP服务器
	log.Printf("HTTP服务器启动，监听地址: %s", httpAddr)
	err = http.ListenAndServe(httpAddr, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "HTTP服务器启动失败: %v\n", err)
		os.Exit(1)
	}
}

// ConnectToAPI 连接到Xray API服务器
func ConnectToAPI(apiAddr string, timeout int) (*grpc.ClientConn, context.Context, func(), error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	conn, err := grpc.DialContext(ctx, apiAddr, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	if err != nil {
		cancel()
		return nil, nil, nil, err
	}

	cleanup := func() {
		cancel()
		conn.Close()
	}

	return conn, ctx, cleanup, nil
}

// 注册所有HTTP处理器
func registerHandlers() {
	// 测试API
	http.HandleFunc("/api/test", HandleTestAPI())

	// 入站相关
	http.HandleFunc("/api/inbounds/socks", HandleAddSocksInbound())
	http.HandleFunc("/api/inbounds/socks/uri", HandleAddSocksInbound()) // 显式支持通过URI添加socks入站
	http.HandleFunc("/api/inbounds/remove", HandleRemoveInbound())
	http.HandleFunc("/api/inbounds/list", HandleListInbounds())

	// 出站相关
	http.HandleFunc("/api/outbounds/uri", HandleAddOutboundFromURI())
	http.HandleFunc("/api/outbounds", HandleAddOutbound())
	http.HandleFunc("/api/outbounds/remove", HandleRemoveOutbound())
	http.HandleFunc("/api/outbounds/list", HandleListOutbounds())

	// 规则相关
	http.HandleFunc("/api/rules", HandleAddRules())
	http.HandleFunc("/api/rules/remove", HandleRemoveRule())
	http.HandleFunc("/api/add_rule", HandleAddSingleRule())
	http.HandleFunc("/api/rules/list", HandleListRules())

	// 其他功能
	http.HandleFunc("/api/stats", HandleStats())
	http.HandleFunc("/debug/routes", HandleDebugRoutes())
	http.HandleFunc("/api/reload", HandleReload())
}
