package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	handlerService "github.com/xtls/xray-core/app/proxyman/command"
	routerService "github.com/xtls/xray-core/app/router/command"
	statsService "github.com/xtls/xray-core/app/stats/command"
	"github.com/xtls/xray-core/common/serial"
	jsonconf "github.com/xtls/xray-core/infra/conf/serial"
)

// 测试处理器
func HandleTestAPI() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("收到测试请求: %s %s", r.Method, r.URL.Path)

		conn, ctx, cleanup, err := ConnectToAPI(apiAddr, timeout)
		if err != nil {
			log.Printf("无法连接到API服务器 %s: %v", apiAddr, err)
			SendJSONResponse(w, false, fmt.Sprintf("连接API服务器失败: %v", err), nil)
			return
		}
		defer cleanup()

		// 添加一些使用conn和ctx的逻辑，避免未使用警告
		_ = conn
		_ = ctx

		SendJSONResponse(w, true, fmt.Sprintf("成功连接到API服务器 %s", apiAddr), nil)
	}
}

// 获取统计信息处理器
func HandleStats() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("收到获取统计信息请求: %s %s", r.Method, r.URL.Path)

		// 连接到API服务器
		conn, ctx, cleanup, err := ConnectToAPI(apiAddr, timeout)
		if err != nil {
			log.Printf("连接API服务器失败: %v", err)
			SendJSONResponse(w, false, "连接API服务器失败: "+err.Error(), nil)
			return
		}
		defer cleanup()

		// 获取统计信息
		client := statsService.NewStatsServiceClient(conn)
		req := &statsService.QueryStatsRequest{
			Pattern: "",
			Reset_:  false,
		}

		resp, err := client.QueryStats(ctx, req)
		if err != nil {
			log.Printf("获取统计信息失败: %v", err)
			SendJSONResponse(w, false, "获取统计信息失败: "+err.Error(), nil)
			return
		}

		// 格式化统计数据
		stats := make(map[string]int64)
		for _, stat := range resp.Stat {
			stats[stat.Name] = stat.Value
		}

		log.Printf("获取统计信息成功")
		SendJSONResponse(w, true, "获取统计信息成功", stats)
	}
}

// 调试路由规则处理器
func HandleDebugRoutes() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("收到查看路由规则请求: %s %s", r.Method, r.URL.Path)

		// 连接到API服务器
		conn, ctx, cleanup, err := ConnectToAPI(apiAddr, timeout)
		if err != nil {
			log.Printf("连接API服务器失败: %v", err)
			SendJSONResponse(w, false, "连接API服务器失败: "+err.Error(), nil)
			return
		}
		defer cleanup()

		// 获取路由规则
		client := routerService.NewRoutingServiceClient(conn)

		// 创建一个空的测试请求
		testReq := &routerService.TestRouteRequest{
			RoutingContext: &routerService.RoutingContext{
				InboundTag: "",
			},
		}

		// 获取API端点列表和xray路由规则信息
		routeInfo := map[string]interface{}{
			"api_endpoints": []string{
				"/api/test",
				"/api/inbounds/socks",
				"/api/inbounds/remove",
				"/api/outbounds/uri",
				"/api/outbounds",
				"/api/outbounds/remove",
				"/api/rules",
				"/api/rules/remove",
				"/api/stats",
				"/debug/routes",
			},
		}

		// 尝试测试路由
		routeResp, routeErr := client.TestRoute(ctx, testReq)
		if routeErr == nil && routeResp != nil {
			routeInfo["route_test_result"] = routeResp
		}

		// 尝试获取平衡器信息
		balancerReq := &routerService.GetBalancerInfoRequest{
			Tag: "", // 空标签获取所有平衡器
		}

		balancerResp, balancerErr := client.GetBalancerInfo(ctx, balancerReq)
		if balancerErr == nil && balancerResp != nil && balancerResp.Balancer != nil {
			// 平衡器信息可用
			routeInfo["balancers"] = balancerResp.Balancer
		}

		log.Printf("获取路由规则信息成功")
		SendJSONResponse(w, true, "获取路由和API端点信息成功", routeInfo)
	}
}

// 获取所有入站列表处理器
func HandleListInbounds() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("收到获取入站列表请求: %s %s", r.Method, r.URL.Path)

		// 从配置获取入站列表
		inbounds := GetInbounds()

		log.Printf("获取入站列表成功，共 %d 个入站", len(inbounds))
		SendJSONResponse(w, true, "获取入站列表成功", inbounds)
	}
}

// 获取所有出站列表处理器
func HandleListOutbounds() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("收到获取出站列表请求: %s %s", r.Method, r.URL.Path)

		// 从配置获取出站列表
		outbounds := GetOutbounds()

		log.Printf("获取出站列表成功，共 %d 个出站", len(outbounds))
		SendJSONResponse(w, true, "获取出站列表成功", outbounds)
	}
}

// 获取所有路由规则列表处理器
func HandleListRules() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("收到获取路由规则列表请求: %s %s", r.Method, r.URL.Path)

		// 从配置获取规则列表
		allRules := GetRules()

		// 过滤掉API相关的规则
		var filteredRules []RuleConfig
		for _, rule := range allRules {
			// 跳过API相关的规则
			if rule.OutboundTag == "api" {
				continue
			}

			// 检查inboundTag是否包含api-in
			isApiRule := false
			for _, tag := range rule.InboundTag {
				if tag == "api-in" {
					isApiRule = true
					break
				}
			}

			if !isApiRule {
				filteredRules = append(filteredRules, rule)
			}
		}

		// 尝试从Xray获取路由信息
		log.Printf("尝试从Xray获取原始路由信息")
		conn, ctx, cleanup, err := ConnectToAPI(apiAddr, timeout)
		if err != nil {
			log.Printf("连接API服务器失败，只返回本地规则: %v", err)
		} else {
			defer cleanup()

			// 尝试获取原始路由信息
			client := routerService.NewRoutingServiceClient(conn)

			// 创建一个空的测试请求
			testReq := &routerService.TestRouteRequest{
				RoutingContext: &routerService.RoutingContext{
					InboundTag: "",
				},
			}

			// 获取路由信息
			routeResp, routeErr := client.TestRoute(ctx, testReq)
			if routeErr == nil && routeResp != nil {
				log.Printf("获取到Xray路由信息: %v", routeResp)
			}
		}

		log.Printf("获取路由规则列表成功，共 %d 个规则（过滤前 %d 个）", len(filteredRules), len(allRules))
		SendJSONResponse(w, true, "获取路由规则列表成功", filteredRules)
	}
}

// 添加Socks入站处理器
func HandleAddSocksInbound() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("收到添加Socks入站请求: %s %s", r.Method, r.URL.Path)

		if r.Method != http.MethodPost {
			log.Printf("错误的请求方法: %s, 期望: POST", r.Method)
			http.Error(w, "只支持POST方法", http.StatusMethodNotAllowed)
			return
		}

		// 读取请求体
		body, _ := io.ReadAll(r.Body)
		log.Printf("收到请求体: %s", string(body))

		// 检查是否是通过socks链接添加
		var uriRequest struct {
			Uri string `json:"uri"`
			Tag string `json:"tag"`
		}

		err := json.Unmarshal(body, &uriRequest)
		if err == nil && uriRequest.Uri != "" && strings.HasPrefix(uriRequest.Uri, "socks://") {
			log.Printf("检测到Socks链接添加方式: %s", uriRequest.Uri)

			// 如果没有指定tag，生成一个默认的
			if uriRequest.Tag == "" {
				uriRequest.Tag = fmt.Sprintf("socks_in_%d", time.Now().Unix())
				log.Printf("未指定Tag，使用默认值: %s", uriRequest.Tag)
			}

			// 解析socks链接并创建入站配置
			configJSON, err := parseSocksInboundURI(uriRequest.Uri, uriRequest.Tag)
			if err != nil {
				log.Printf("解析socks链接失败: %v", err)
				SendJSONResponse(w, false, "解析socks链接失败: "+err.Error(), nil)
				return
			}

			log.Printf("从socks链接生成的配置: %s", configJSON)

			// 使用生成的配置
			conf, err := jsonconf.DecodeJSONConfig(strings.NewReader(configJSON))
			if err != nil {
				log.Printf("配置解析失败: %v", err)
				SendJSONResponse(w, false, "配置解析失败: "+err.Error(), nil)
				return
			}

			if len(conf.InboundConfigs) == 0 {
				log.Printf("没有有效的入站配置")
				SendJSONResponse(w, false, "没有有效的入站配置", nil)
				return
			}

			// 连接到API服务器并添加入站
			conn, ctx, cleanup, err := ConnectToAPI(apiAddr, timeout)
			if err != nil {
				log.Printf("连接API服务器失败: %v", err)
				SendJSONResponse(w, false, "连接API服务器失败: "+err.Error(), nil)
				return
			}
			defer cleanup()

			// 添加入站
			client := handlerService.NewHandlerServiceClient(conn)
			inboundConf := conf.InboundConfigs[0]
			i, err := inboundConf.Build()
			if err != nil {
				log.Printf("构建配置失败: %v", err)
				SendJSONResponse(w, false, "构建配置失败: "+err.Error(), nil)
				return
			}

			req := &handlerService.AddInboundRequest{
				Inbound: i,
			}
			resp, err := client.AddInbound(ctx, req)
			if err != nil {
				log.Printf("添加入站失败: %v", err)
				SendJSONResponse(w, false, "添加入站失败: "+err.Error(), nil)
				return
			}

			log.Printf("入站添加成功: %s", uriRequest.Tag)

			// 保存入站配置
			inboundConfig := InboundConfig{
				Tag:      uriRequest.Tag,
				Protocol: "socks",
				Settings: make(map[string]interface{}),
			}

			// 尝试从JSON配置提取端口信息
			var metaData map[string]interface{}
			inboundJSON, _ := json.Marshal(inboundConf)
			if jsonErr := json.Unmarshal(inboundJSON, &metaData); jsonErr == nil {
				if portValue, ok := metaData["port"]; ok {
					if portStr, ok := portValue.(string); ok {
						portNum, portErr := strconv.Atoi(portStr)
						if portErr == nil {
							inboundConfig.Port = portNum
						}
					} else if portInt, ok := portValue.(float64); ok {
						inboundConfig.Port = int(portInt)
					} else if portInt, ok := portValue.(int); ok {
						inboundConfig.Port = portInt
					}
				}
			}

			// 添加监听地址
			if inboundConf.ListenOn != nil {
				inboundConfig.Listen = inboundConf.ListenOn.String()
			}

			// 尝试提取设置信息
			if inboundConf.Settings != nil {
				var settings map[string]interface{}
				settingsJSON, _ := json.Marshal(inboundConf.Settings)
				json.Unmarshal(settingsJSON, &settings)
				inboundConfig.Settings = settings
			}

			// 保存到配置
			AddInbound(inboundConfig)

			// 如果启用了保存到官方配置
			if saveToConfig {
				// 检查configPath是否指向HTTP API自己的配置文件
				if configPath == GetConfigFileName() {
					log.Printf("警告: 配置路径指向HTTP API配置文件，跳过重复保存")
				} else {
					err := SaveToXrayConfig(configPath, &inboundConfig, nil, nil)
					if err != nil {
						log.Printf("保存到Xray配置文件失败: %v", err)
					} else {
						log.Printf("成功保存入站 %s 到Xray配置文件", inboundConfig.Tag)
					}
				}
			}

			SendJSONResponse(w, true, "成功添加入站: "+uriRequest.Tag, resp)
			return
		}

		// 如果不是通过socks链接添加，则使用原有的方式处理
		conf, err := jsonconf.DecodeJSONConfig(strings.NewReader(string(body)))
		if err != nil {
			log.Printf("配置解析失败: %v", err)
			SendJSONResponse(w, false, "配置解析失败: "+err.Error(), nil)
			return
		}

		if len(conf.InboundConfigs) == 0 {
			log.Printf("没有有效的入站配置")
			SendJSONResponse(w, false, "没有有效的入站配置", nil)
			return
		}

		// 连接到API服务器
		log.Printf("连接到API服务器: %s", apiAddr)
		conn, ctx, cleanup, err := ConnectToAPI(apiAddr, timeout)
		if err != nil {
			log.Printf("连接API服务器失败: %v", err)
			SendJSONResponse(w, false, "连接API服务器失败: "+err.Error(), nil)
			return
		}
		defer cleanup()

		// 添加入站
		client := handlerService.NewHandlerServiceClient(conn)

		successCount := 0
		var lastError error
		var lastResponse interface{}

		for _, in := range conf.InboundConfigs {
			log.Printf("构建入站配置: %s", in.Tag)
			i, err := in.Build()
			if err != nil {
				log.Printf("构建配置失败: %v", err)
				lastError = err
				continue
			}

			log.Printf("发送添加入站请求")
			req := &handlerService.AddInboundRequest{
				Inbound: i,
			}
			resp, err := client.AddInbound(ctx, req)
			if err != nil {
				log.Printf("添加入站失败: %v", err)
				lastError = err
				continue
			}

			log.Printf("入站添加成功: %s", in.Tag)
			successCount++
			lastResponse = resp

			// 保存成功添加的入站到配置文件
			inboundConfig := InboundConfig{
				Tag:      in.Tag,
				Protocol: in.Protocol,
				Settings: make(map[string]interface{}),
			}

			// 尝试从JSON配置提取端口信息
			var metaData map[string]interface{}
			configJSON, _ := json.Marshal(in)
			if err := json.Unmarshal(configJSON, &metaData); err == nil {
				if portValue, ok := metaData["port"]; ok {
					if portStr, ok := portValue.(string); ok {
						port, err := strconv.Atoi(portStr)
						if err == nil {
							inboundConfig.Port = port
						}
					} else if portInt, ok := portValue.(float64); ok {
						inboundConfig.Port = int(portInt)
					} else if portInt, ok := portValue.(int); ok {
						inboundConfig.Port = portInt
					}
				}
			}

			// 添加监听地址
			if in.ListenOn != nil {
				inboundConfig.Listen = in.ListenOn.String()
			}

			// 尝试提取设置信息
			if in.Settings != nil {
				var settings map[string]interface{}
				settingsJSON, _ := json.Marshal(in.Settings)
				json.Unmarshal(settingsJSON, &settings)
				inboundConfig.Settings = settings
			}

			// 保存到配置
			AddInbound(inboundConfig)

			// 如果启用了保存到官方配置
			if saveToConfig {
				// 检查configPath是否指向HTTP API自己的配置文件
				if configPath == GetConfigFileName() {
					log.Printf("警告: 配置路径指向HTTP API配置文件，跳过重复保存")
				} else {
					err := SaveToXrayConfig(configPath, &inboundConfig, nil, nil)
					if err != nil {
						log.Printf("保存到Xray配置文件失败: %v", err)
					} else {
						log.Printf("成功保存入站 %s 到Xray配置文件", inboundConfig.Tag)
					}
				}
			}
		}

		if successCount > 0 {
			SendJSONResponse(w, true, fmt.Sprintf("成功添加%d个入站", successCount), lastResponse)
		} else {
			SendJSONResponse(w, false, "添加入站失败: "+lastError.Error(), nil)
		}
	}
}

func HandleRemoveInbound() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("收到删除入站请求: %s %s", r.Method, r.URL.Path)

		if r.Method != http.MethodPost && r.Method != http.MethodDelete {
			log.Printf("错误的请求方法: %s, 期望: POST或DELETE", r.Method)
			http.Error(w, "只支持POST或DELETE方法", http.StatusMethodNotAllowed)
			return
		}

		// 读取请求体
		var request struct {
			Tag string `json:"tag"`
		}

		err := json.NewDecoder(r.Body).Decode(&request)
		if err != nil {
			log.Printf("解析请求失败: %v", err)
			SendJSONResponse(w, false, "解析请求失败: "+err.Error(), nil)
			return
		}

		if request.Tag == "" {
			log.Printf("缺少入站标签")
			SendJSONResponse(w, false, "缺少入站标签(tag)", nil)
			return
		}

		log.Printf("准备删除入站: %s", request.Tag)

		// 连接到API服务器
		conn, ctx, cleanup, err := ConnectToAPI(apiAddr, timeout)
		if err != nil {
			log.Printf("连接API服务器失败: %v", err)
			SendJSONResponse(w, false, "连接API服务器失败: "+err.Error(), nil)
			return
		}
		defer cleanup()

		// 删除入站
		client := handlerService.NewHandlerServiceClient(conn)
		req := &handlerService.RemoveInboundRequest{
			Tag: request.Tag,
		}

		resp, err := client.RemoveInbound(ctx, req)
		if err != nil {
			log.Printf("删除入站失败: %v", err)
			SendJSONResponse(w, false, "删除入站失败: "+err.Error(), nil)
			return
		}

		log.Printf("入站删除成功: %s", request.Tag)
		// 从配置中移除
		RemoveInbound(request.Tag)

		// 如果启用了保存到官方配置
		if saveToConfig {
			// 检查configPath是否指向HTTP API自己的配置文件
			if configPath == GetConfigFileName() {
				log.Printf("警告: 配置路径指向HTTP API配置文件，跳过重复保存")
			} else {
				err := RemoveFromXrayConfig(configPath, request.Tag, "", "")
				if err != nil {
					log.Printf("从Xray配置文件移除入站失败: %v", err)
				} else {
					log.Printf("成功从Xray配置文件移除入站 %s", request.Tag)
				}
			}
		}

		SendJSONResponse(w, true, fmt.Sprintf("入站 %s 删除成功", request.Tag), resp)
	}
}

func HandleAddOutboundFromURI() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("收到从URI添加出站请求: %s %s", r.Method, r.URL.Path)

		if r.Method != http.MethodPost {
			log.Printf("错误的请求方法: %s, 期望: POST", r.Method)
			http.Error(w, "只支持POST方法", http.StatusMethodNotAllowed)
			return
		}

		// 读取请求体
		var request struct {
			Uri string `json:"uri"`
			Tag string `json:"tag"`
		}

		err := json.NewDecoder(r.Body).Decode(&request)
		if err != nil {
			log.Printf("解析请求失败: %v", err)
			SendJSONResponse(w, false, "解析请求失败: "+err.Error(), nil)
			return
		}

		if request.Uri == "" {
			log.Printf("缺少URI")
			SendJSONResponse(w, false, "缺少URI", nil)
			return
		}

		if request.Tag == "" {
			log.Printf("缺少出站标签")
			SendJSONResponse(w, false, "缺少出站标签(tag)", nil)
			return
		}

		log.Printf("处理URI: %s, Tag: %s", request.Uri, request.Tag)

		// 解析URI并创建出站配置
		var configJSON string

		if strings.HasPrefix(request.Uri, "vmess://") {
			log.Printf("检测到vmess协议")
			configJSON, err = parseVmessURI(request.Uri, request.Tag)
			if err != nil {
				log.Printf("解析vmess URI失败: %v", err)
				SendJSONResponse(w, false, "解析vmess URI失败: "+err.Error(), nil)
				return
			}
		} else if strings.HasPrefix(request.Uri, "vless://") {
			log.Printf("检测到vless协议")
			configJSON, err = parseVlessURI(request.Uri, request.Tag)
			if err != nil {
				log.Printf("解析vless URI失败: %v", err)
				SendJSONResponse(w, false, "解析vless URI失败: "+err.Error(), nil)
				return
			}
		} else if strings.HasPrefix(request.Uri, "trojan://") {
			log.Printf("检测到trojan协议")
			configJSON, err = parseTrojanURI(request.Uri, request.Tag)
			if err != nil {
				log.Printf("解析trojan URI失败: %v", err)
				SendJSONResponse(w, false, "解析trojan URI失败: "+err.Error(), nil)
				return
			}
		} else if strings.HasPrefix(request.Uri, "ss://") {
			log.Printf("检测到shadowsocks协议")
			configJSON, err = parseShadowsocksURI(request.Uri, request.Tag)
			if err != nil {
				log.Printf("解析shadowsocks URI失败: %v", err)
				SendJSONResponse(w, false, "解析shadowsocks URI失败: "+err.Error(), nil)
				return
			}
		} else if strings.HasPrefix(request.Uri, "socks://") {
			log.Printf("检测到socks协议")
			configJSON, err = parseSocksURI(request.Uri, request.Tag)
			if err != nil {
				log.Printf("解析socks URI失败: %v", err)
				SendJSONResponse(w, false, "解析socks URI失败: "+err.Error(), nil)
				return
			}
		} else {
			log.Printf("不支持的URI协议: %s", request.Uri)
			SendJSONResponse(w, false, "不支持的URI协议，目前支持vmess://、vless://、trojan://、ss://和socks://", nil)
			return
		}

		log.Printf("生成的出站配置: %s", configJSON)

		// 解析配置JSON
		conf, err := jsonconf.DecodeJSONConfig(strings.NewReader(configJSON))
		if err != nil {
			log.Printf("配置解析失败: %v", err)
			SendJSONResponse(w, false, "配置解析失败: "+err.Error(), nil)
			return
		}

		if len(conf.OutboundConfigs) == 0 {
			log.Printf("没有有效的出站配置")
			SendJSONResponse(w, false, "没有有效的出站配置", nil)
			return
		}

		// 连接到API服务器
		conn, ctx, cleanup, err := ConnectToAPI(apiAddr, timeout)
		if err != nil {
			log.Printf("连接API服务器失败: %v", err)
			SendJSONResponse(w, false, "连接API服务器失败: "+err.Error(), nil)
			return
		}
		defer cleanup()

		// 添加出站
		client := handlerService.NewHandlerServiceClient(conn)
		outboundConf := conf.OutboundConfigs[0]
		o, err := outboundConf.Build()
		if err != nil {
			log.Printf("构建配置失败: %v", err)
			SendJSONResponse(w, false, "构建配置失败: "+err.Error(), nil)
			return
		}
		req := &handlerService.AddOutboundRequest{
			Outbound: o,
		}
		resp, err := client.AddOutbound(ctx, req)
		if err != nil {
			log.Printf("添加出站失败: %v", err)
			SendJSONResponse(w, false, "添加出站失败: "+err.Error(), nil)
			return
		}

		log.Printf("出站添加成功: %s", request.Tag)

		// 保存出站配置
		outboundConfig := OutboundConfig{
			Tag:      request.Tag,
			Protocol: outboundConf.Protocol,
			Settings: make(map[string]interface{}),
		}

		// 尝试提取设置信息
		if outboundConf.Settings != nil {
			var settings map[string]interface{}
			settingsJSON, _ := json.Marshal(outboundConf.Settings)
			json.Unmarshal(settingsJSON, &settings)
			outboundConfig.Settings = settings

			// 尝试获取地址和端口
			if protocol := outboundConf.Protocol; protocol == "vmess" || protocol == "vless" {
				if vnext, ok := settings["vnext"].([]interface{}); ok && len(vnext) > 0 {
					if server, ok := vnext[0].(map[string]interface{}); ok {
						if addr, ok := server["address"].(string); ok {
							outboundConfig.Address = addr
						}
						if port, ok := server["port"].(float64); ok {
							outboundConfig.Port = int(port)
						}
					}
				}
			} else if protocol == "shadowsocks" || protocol == "trojan" {
				if servers, ok := settings["servers"].([]interface{}); ok && len(servers) > 0 {
					if server, ok := servers[0].(map[string]interface{}); ok {
						if addr, ok := server["address"].(string); ok {
							outboundConfig.Address = addr
						}
						if port, ok := server["port"].(float64); ok {
							outboundConfig.Port = int(port)
						}
					}
				}
			}
		}

		// 尝试提取流设置
		if outboundConf.StreamSetting != nil {
			var streamSettings map[string]interface{}
			streamJSON, _ := json.Marshal(outboundConf.StreamSetting)
			json.Unmarshal(streamJSON, &streamSettings)
			outboundConfig.StreamSettings = streamSettings
		}

		// 保存到配置
		AddOutbound(outboundConfig)

		// 如果启用了保存到官方配置
		if saveToConfig {
			// 检查configPath是否指向HTTP API自己的配置文件
			if configPath == GetConfigFileName() {
				log.Printf("警告: 配置路径指向HTTP API配置文件，跳过重复保存")
			} else {
				err := SaveToXrayConfig(configPath, nil, &outboundConfig, nil)
				if err != nil {
					log.Printf("保存到Xray配置文件失败: %v", err)
				} else {
					log.Printf("成功保存出站 %s 到Xray配置文件", outboundConfig.Tag)
				}
			}
		}

		SendJSONResponse(w, true, "出站添加成功", resp)
	}
}

// 解析vmess URI
func parseVmessURI(uri string, tag string) (string, error) {
	// 移除vmess://前缀
	encodedPart := strings.TrimPrefix(uri, "vmess://")

	// Base64解码
	decodedBytes, err := base64.StdEncoding.DecodeString(encodedPart)
	if err != nil {
		// 尝试使用URL安全的Base64解码
		decodedBytes, err = base64.RawURLEncoding.DecodeString(encodedPart)
		if err != nil {
			return "", fmt.Errorf("Base64解码失败: %v", err)
		}
	}

	// 解析JSON
	var vmessInfo struct {
		V             string `json:"v"`
		PS            string `json:"ps"`
		Add           string `json:"add"`
		Port          int    `json:"port"`
		ID            string `json:"id"`
		Aid           int    `json:"aid"`
		Net           string `json:"net"`
		Type          string `json:"type"`
		Host          string `json:"host"`
		Path          string `json:"path"`
		TLS           string `json:"tls"`
		SNI           string `json:"sni"`
		Alpn          string `json:"alpn"`
		Scy           string `json:"scy"`
		FP            string `json:"fp"`
		AllowInsecure int    `json:"allowInsecure"`
	}

	err = json.Unmarshal(decodedBytes, &vmessInfo)
	if err != nil {
		return "", fmt.Errorf("解析vmess配置失败: %v", err)
	}

	// 默认值处理
	if vmessInfo.Net == "" {
		vmessInfo.Net = "tcp"
	}
	if vmessInfo.Type == "" {
		vmessInfo.Type = "none"
	}
	if vmessInfo.Scy == "" {
		vmessInfo.Scy = "auto"
	}

	// 构建出站配置
	outboundConfig := map[string]interface{}{
		"tag":      tag,
		"protocol": "vmess",
		"settings": map[string]interface{}{
			"vnext": []map[string]interface{}{
				{
					"address": vmessInfo.Add,
					"port":    vmessInfo.Port,
					"users": []map[string]interface{}{
						{
							"id":       vmessInfo.ID,
							"alterId":  vmessInfo.Aid,
							"security": vmessInfo.Scy,
						},
					},
				},
			},
		},
		"streamSettings": map[string]interface{}{
			"network": vmessInfo.Net,
		},
	}

	// 添加stream设置
	streamSettings := outboundConfig["streamSettings"].(map[string]interface{})

	// TLS设置
	if vmessInfo.TLS == "tls" {
		streamSettings["security"] = "tls"
		tlsSettings := map[string]interface{}{
			"allowInsecure": vmessInfo.AllowInsecure == 1,
			"serverName":    vmessInfo.SNI,
		}
		if vmessInfo.SNI == "" && vmessInfo.Host != "" {
			tlsSettings["serverName"] = vmessInfo.Host
		}
		if vmessInfo.FP != "" {
			tlsSettings["fingerprint"] = vmessInfo.FP
		}
		if vmessInfo.Alpn != "" {
			// 分割ALPN字符串
			tlsSettings["alpn"] = strings.Split(vmessInfo.Alpn, ",")
		}
		streamSettings["tlsSettings"] = tlsSettings
	}

	// 根据传输协议添加特定设置
	switch vmessInfo.Net {
	case "tcp":
		if vmessInfo.Type == "http" {
			httpSettings := map[string]interface{}{}
			if vmessInfo.Host != "" {
				httpSettings["host"] = strings.Split(vmessInfo.Host, ",")
			}
			if vmessInfo.Path != "" {
				httpSettings["path"] = vmessInfo.Path
			}
			streamSettings["tcpSettings"] = map[string]interface{}{
				"header": map[string]interface{}{
					"type":    "http",
					"request": httpSettings,
				},
			}
		}
	case "kcp":
		kcpSettings := map[string]interface{}{}
		if vmessInfo.Type != "" {
			kcpSettings["header"] = map[string]interface{}{
				"type": vmessInfo.Type,
			}
		}
		if vmessInfo.Path != "" {
			kcpSettings["seed"] = vmessInfo.Path
		}
		streamSettings["kcpSettings"] = kcpSettings
	case "ws":
		wsSettings := map[string]interface{}{}
		if vmessInfo.Path != "" {
			wsSettings["path"] = vmessInfo.Path
		}
		if vmessInfo.Host != "" {
			wsSettings["headers"] = map[string]interface{}{
				"Host": vmessInfo.Host,
			}
		}
		streamSettings["wsSettings"] = wsSettings
	case "h2", "http":
		h2Settings := map[string]interface{}{}
		if vmessInfo.Path != "" {
			h2Settings["path"] = vmessInfo.Path
		}
		if vmessInfo.Host != "" {
			h2Settings["host"] = strings.Split(vmessInfo.Host, ",")
		}
		streamSettings["httpSettings"] = h2Settings
	case "quic":
		quicSettings := map[string]interface{}{}
		if vmessInfo.Type != "" {
			quicSettings["header"] = map[string]interface{}{
				"type": vmessInfo.Type,
			}
		}
		if vmessInfo.Host != "" {
			quicSettings["security"] = vmessInfo.Host
		}
		if vmessInfo.Path != "" {
			quicSettings["key"] = vmessInfo.Path
		}
		streamSettings["quicSettings"] = quicSettings
	case "grpc":
		grpcSettings := map[string]interface{}{}
		if vmessInfo.Path != "" {
			grpcSettings["serviceName"] = vmessInfo.Path
		}
		if vmessInfo.Type == "multi" {
			grpcSettings["multiMode"] = true
		}
		streamSettings["grpcSettings"] = grpcSettings
	}

	// 转为JSON
	fullConfig := map[string]interface{}{
		"outbounds": []interface{}{outboundConfig},
	}

	jsonData, err := json.MarshalIndent(fullConfig, "", "  ")
	if err != nil {
		return "", fmt.Errorf("序列化配置失败: %v", err)
	}

	return string(jsonData), nil
}

// 解析vless URI
func parseVlessURI(uri string, tag string) (string, error) {
	// 移除vless://前缀
	uri = strings.TrimPrefix(uri, "vless://")

	// 分割URI
	parts := strings.SplitN(uri, "@", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("无效的VLESS URI格式")
	}

	// 获取用户ID
	userID := parts[0]

	// 分割主机和参数部分
	hostAndParams := strings.SplitN(parts[1], "?", 2)
	if len(hostAndParams) < 1 {
		return "", fmt.Errorf("无效的VLESS URI格式")
	}

	// 解析主机和端口
	hostAndPort := strings.SplitN(hostAndParams[0], ":", 2)
	if len(hostAndPort) != 2 {
		return "", fmt.Errorf("无效的主机和端口格式")
	}

	host := hostAndPort[0]
	port, err := strconv.Atoi(hostAndPort[1])
	if err != nil {
		return "", fmt.Errorf("无效的端口: %v", err)
	}

	// 默认值
	params := map[string]string{
		"type":       "tcp",
		"security":   "none",
		"encryption": "none",
	}

	// 解析参数
	if len(hostAndParams) > 1 {
		queryParams := strings.Split(hostAndParams[1], "&")
		for _, param := range queryParams {
			keyValue := strings.SplitN(param, "=", 2)
			if len(keyValue) == 2 {
				// URL解码参数值
				value, err := url.QueryUnescape(keyValue[1])
				if err != nil {
					log.Printf("警告: 无法URL解码参数 %s: %v", keyValue[0], err)
					value = keyValue[1]
				}
				params[keyValue[0]] = value
			}
		}
	}

	// 构建基本出站配置
	outboundConfig := map[string]interface{}{
		"tag":      tag,
		"protocol": "vless",
		"settings": map[string]interface{}{
			"vnext": []map[string]interface{}{
				{
					"address": host,
					"port":    port,
					"users": []map[string]interface{}{
						{
							"id":         userID,
							"encryption": params["encryption"],
						},
					},
				},
			},
		},
		"streamSettings": map[string]interface{}{
			"network": params["type"],
		},
	}

	// 添加flow参数
	if flow, ok := params["flow"]; ok && flow != "" {
		outboundConfig["settings"].(map[string]interface{})["vnext"].([]map[string]interface{})[0]["users"].([]map[string]interface{})[0]["flow"] = flow
	}

	// 添加stream设置
	streamSettings := outboundConfig["streamSettings"].(map[string]interface{})

	// TLS设置
	if params["security"] == "tls" {
		streamSettings["security"] = "tls"
		tlsSettings := map[string]interface{}{}

		// 添加SNI
		if sni, ok := params["sni"]; ok && sni != "" {
			// 移除SNI中的#号及其后面的部分
			hashIndex := strings.Index(sni, "#")
			if hashIndex > 0 {
				sni = sni[:hashIndex]
			}
			tlsSettings["serverName"] = sni
		} else if host != "" {
			// 移除主机名中的#号及其后面的部分
			hashIndex := strings.Index(host, "#")
			if hashIndex > 0 {
				host = host[:hashIndex]
			}
			tlsSettings["serverName"] = host
		}

		// 添加alpn
		if alpn, ok := params["alpn"]; ok && alpn != "" {
			tlsSettings["alpn"] = strings.Split(alpn, ",")
		}

		// 添加fingerprint
		if fp, ok := params["fp"]; ok && fp != "" {
			tlsSettings["fingerprint"] = fp
		}

		// 添加allowInsecure
		if insecure, ok := params["allowInsecure"]; ok {
			tlsSettings["allowInsecure"] = insecure == "1"
		}

		streamSettings["tlsSettings"] = tlsSettings
	} else if params["security"] == "reality" {
		streamSettings["security"] = "reality"
		realitySettings := map[string]interface{}{}

		// Reality 特有参数
		if sni, ok := params["sni"]; ok && sni != "" {
			// 移除SNI中的#号及其后面的部分
			hashIndex := strings.Index(sni, "#")
			if hashIndex > 0 {
				sni = sni[:hashIndex]
			}
			realitySettings["serverName"] = sni
		}

		if pbk, ok := params["pbk"]; ok && pbk != "" {
			realitySettings["publicKey"] = pbk
		}

		if sid, ok := params["sid"]; ok && sid != "" {
			realitySettings["shortId"] = sid
		}

		if spx, ok := params["spx"]; ok && spx != "" {
			realitySettings["spiderX"] = spx
		}

		if fp, ok := params["fp"]; ok && fp != "" {
			realitySettings["fingerprint"] = fp
		}

		streamSettings["realitySettings"] = realitySettings
	}

	// 根据传输协议添加特定设置
	switch params["type"] {
	case "tcp":
		if headerType, ok := params["headerType"]; ok && headerType == "http" {
			tcpSettings := map[string]interface{}{
				"header": map[string]interface{}{
					"type": "http",
				},
			}

			// 如果有path参数
			if path, ok := params["path"]; ok && path != "" {
				tcpSettings["header"].(map[string]interface{})["request"] = map[string]interface{}{
					"path": strings.Split(path, ","),
				}
			}

			// 如果有host参数
			if host, ok := params["host"]; ok && host != "" {
				if request, ok := tcpSettings["header"].(map[string]interface{})["request"].(map[string]interface{}); ok {
					request["headers"] = map[string]interface{}{
						"Host": strings.Split(host, ","),
					}
				} else {
					tcpSettings["header"].(map[string]interface{})["request"] = map[string]interface{}{
						"headers": map[string]interface{}{
							"Host": strings.Split(host, ","),
						},
					}
				}
			}

			streamSettings["tcpSettings"] = tcpSettings
		}
	case "kcp":
		kcpSettings := map[string]interface{}{}
		if seed, ok := params["seed"]; ok && seed != "" {
			kcpSettings["seed"] = seed
		}
		if headerType, ok := params["headerType"]; ok && headerType != "" {
			kcpSettings["header"] = map[string]interface{}{
				"type": headerType,
			}
		}
		streamSettings["kcpSettings"] = kcpSettings
	case "ws":
		wsSettings := map[string]interface{}{}
		if path, ok := params["path"]; ok && path != "" {
			wsSettings["path"] = path
		}
		if host, ok := params["host"]; ok && host != "" {
			wsSettings["headers"] = map[string]interface{}{
				"Host": host,
			}
		}
		streamSettings["wsSettings"] = wsSettings
	case "h2", "http":
		h2Settings := map[string]interface{}{}
		if path, ok := params["path"]; ok && path != "" {
			h2Settings["path"] = path
		}
		if host, ok := params["host"]; ok && host != "" {
			h2Settings["host"] = strings.Split(host, ",")
		}
		streamSettings["httpSettings"] = h2Settings
	case "quic":
		quicSettings := map[string]interface{}{}
		if headerType, ok := params["headerType"]; ok && headerType != "" {
			quicSettings["header"] = map[string]interface{}{
				"type": headerType,
			}
		}
		if quicSecurity, ok := params["quicSecurity"]; ok && quicSecurity != "" {
			quicSettings["security"] = quicSecurity
			if key, ok := params["key"]; ok && key != "" {
				quicSettings["key"] = key
			}
		}
		streamSettings["quicSettings"] = quicSettings
	case "grpc":
		grpcSettings := map[string]interface{}{}
		if serviceName, ok := params["serviceName"]; ok && serviceName != "" {
			grpcSettings["serviceName"] = serviceName
		}
		if mode, ok := params["mode"]; ok && mode == "multi" {
			grpcSettings["multiMode"] = true
		}
		streamSettings["grpcSettings"] = grpcSettings
	}

	// 转为JSON
	fullConfig := map[string]interface{}{
		"outbounds": []interface{}{outboundConfig},
	}

	jsonData, err := json.MarshalIndent(fullConfig, "", "  ")
	if err != nil {
		return "", fmt.Errorf("序列化配置失败: %v", err)
	}

	return string(jsonData), nil
}

// 解析trojan URI
func parseTrojanURI(uri string, tag string) (string, error) {
	// trojan链接格式：trojan://password@server:port?security=tls&sni=example.com&type=tcp&headerType=none#remarks
	u, err := url.Parse(uri)
	if err != nil {
		return "", fmt.Errorf("URL解析失败: %v", err)
	}

	if u.Scheme != "trojan" {
		return "", fmt.Errorf("不是有效的trojan链接")
	}

	// 获取必要参数
	password := u.User.Username()
	if password == "" {
		return "", fmt.Errorf("未指定密码")
	}

	server := u.Hostname()
	if server == "" {
		return "", fmt.Errorf("未指定服务器地址")
	}

	port, err := strconv.Atoi(u.Port())
	if err != nil || port <= 0 || port > 65535 {
		return "", fmt.Errorf("无效的端口: %v", u.Port())
	}

	// 获取可选参数
	queryParams := u.Query()

	// 获取安全类型，默认为tls
	security := queryParams.Get("security")
	if security == "" {
		security = "tls"
	}

	// 获取SNI参数
	sni := queryParams.Get("sni")
	if sni == "" {
		// 如果没有sni参数，尝试peer参数(有些客户端使用)
		sni = queryParams.Get("peer")
	}
	if sni == "" {
		// 如果还是没有，默认使用服务器地址
		sni = server
	}

	// 判断是否需要跳过TLS验证
	allowInsecure := queryParams.Get("allowInsecure") == "1"

	// 获取网络类型，默认为tcp
	network := queryParams.Get("type")
	if network == "" {
		network = "tcp"
	}

	// 获取header类型
	headerType := queryParams.Get("headerType")

	// 获取备注
	remark := u.Fragment
	if remark == "" {
		remark = server
	}

	// 构建outbound配置
	// 基本设置
	outboundJSON := fmt.Sprintf(`{
		"outbounds": [
			{
				"protocol": "trojan",
				"settings": {
					"servers": [
						{
							"address": "%s",
							"port": %d,
							"password": "%s"
						}
					]
				},
				"tag": "%s"
			}
		]
	}`, server, port, password, tag)

	// 添加流设置
	if security != "" || network != "" {
		// 重新解析整个JSON
		var jsonObj map[string]interface{}
		err = json.Unmarshal([]byte(outboundJSON), &jsonObj)
		if err != nil {
			return "", fmt.Errorf("JSON处理失败: %v", err)
		}

		// 获取outbounds数组
		outbounds, ok := jsonObj["outbounds"].([]interface{})
		if !ok || len(outbounds) == 0 {
			return "", fmt.Errorf("无效的outbounds配置")
		}

		// 添加streamSettings
		firstOutbound := outbounds[0].(map[string]interface{})
		streamSettings := map[string]interface{}{
			"network": network,
		}

		// 添加安全设置
		if security == "tls" {
			streamSettings["security"] = "tls"
			streamSettings["tlsSettings"] = map[string]interface{}{
				"serverName":    sni,
				"allowInsecure": allowInsecure,
			}
		}

		// 如果指定了headerType，添加对应的头部设置
		if headerType != "" && headerType != "none" {
			switch network {
			case "tcp":
				streamSettings["tcpSettings"] = map[string]interface{}{
					"header": map[string]interface{}{
						"type": headerType,
					},
				}
			case "ws":
				streamSettings["wsSettings"] = map[string]interface{}{
					"path": queryParams.Get("path"),
					"headers": map[string]interface{}{
						"Host": queryParams.Get("host"),
					},
				}
			case "h2":
				streamSettings["httpSettings"] = map[string]interface{}{
					"path": queryParams.Get("path"),
					"host": strings.Split(queryParams.Get("host"), ","),
				}
			case "grpc":
				streamSettings["grpcSettings"] = map[string]interface{}{
					"serviceName": queryParams.Get("serviceName"),
				}
			}
		}

		firstOutbound["streamSettings"] = streamSettings

		// 转回JSON
		newJson, err := json.MarshalIndent(jsonObj, "", "  ")
		if err != nil {
			return "", fmt.Errorf("JSON编码失败: %v", err)
		}

		outboundJSON = string(newJson)
	}

	return outboundJSON, nil
}

func HandleAddOutbound() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("收到添加出站请求: %s %s", r.Method, r.URL.Path)

		if r.Method != http.MethodPost {
			log.Printf("错误的请求方法: %s, 期望: POST", r.Method)
			http.Error(w, "只支持POST方法", http.StatusMethodNotAllowed)
			return
		}

		// 读取请求体
		body, _ := io.ReadAll(r.Body)
		log.Printf("收到请求体: %s", string(body))

		// 直接解析完整的配置JSON
		conf, err := jsonconf.DecodeJSONConfig(strings.NewReader(string(body)))
		if err != nil {
			log.Printf("配置解析失败: %v", err)
			SendJSONResponse(w, false, "配置解析失败: "+err.Error(), nil)
			return
		}

		if len(conf.OutboundConfigs) == 0 {
			log.Printf("没有有效的出站配置")
			SendJSONResponse(w, false, "没有有效的出站配置", nil)
			return
		}

		// 连接到API服务器
		log.Printf("连接到API服务器: %s", apiAddr)
		conn, ctx, cleanup, err := ConnectToAPI(apiAddr, timeout)
		if err != nil {
			log.Printf("连接API服务器失败: %v", err)
			SendJSONResponse(w, false, "连接API服务器失败: "+err.Error(), nil)
			return
		}
		defer cleanup()

		// 添加出站
		client := handlerService.NewHandlerServiceClient(conn)

		successCount := 0
		var lastError error
		var lastResponse interface{}

		for _, out := range conf.OutboundConfigs {
			log.Printf("构建出站配置: %s", out.Tag)
			o, err := out.Build()
			if err != nil {
				log.Printf("构建配置失败: %v", err)
				lastError = err
				continue
			}

			log.Printf("发送添加出站请求")
			req := &handlerService.AddOutboundRequest{
				Outbound: o,
			}
			resp, err := client.AddOutbound(ctx, req)
			if err != nil {
				log.Printf("添加出站失败: %v", err)
				lastError = err
				continue
			}

			log.Printf("出站添加成功: %s", out.Tag)
			successCount++
			lastResponse = resp

			// 保存成功添加的出站到配置文件
			outboundConfig := OutboundConfig{
				Tag:      out.Tag,
				Protocol: out.Protocol,
				Settings: make(map[string]interface{}),
			}

			// 尝试提取设置信息
			if out.Settings != nil {
				var settings map[string]interface{}
				settingsJSON, _ := json.Marshal(out.Settings)
				json.Unmarshal(settingsJSON, &settings)
				outboundConfig.Settings = settings

				// 尝试获取地址和端口
				if protocol := out.Protocol; protocol == "vmess" || protocol == "vless" {
					if vnext, ok := settings["vnext"].([]interface{}); ok && len(vnext) > 0 {
						if server, ok := vnext[0].(map[string]interface{}); ok {
							if addr, ok := server["address"].(string); ok {
								outboundConfig.Address = addr
							}
							if port, ok := server["port"].(float64); ok {
								outboundConfig.Port = int(port)
							}
						}
					}
				} else if protocol == "shadowsocks" || protocol == "trojan" {
					if servers, ok := settings["servers"].([]interface{}); ok && len(servers) > 0 {
						if server, ok := servers[0].(map[string]interface{}); ok {
							if addr, ok := server["address"].(string); ok {
								outboundConfig.Address = addr
							}
							if port, ok := server["port"].(float64); ok {
								outboundConfig.Port = int(port)
							}
						}
					}
				}
			}

			// 尝试提取流设置
			if out.StreamSetting != nil {
				var streamSettings map[string]interface{}
				streamJSON, _ := json.Marshal(out.StreamSetting)
				json.Unmarshal(streamJSON, &streamSettings)
				outboundConfig.StreamSettings = streamSettings
			}

			// 保存到配置
			AddOutbound(outboundConfig)

			// 如果启用了保存到官方配置
			if saveToConfig {
				// 检查configPath是否指向HTTP API自己的配置文件
				if configPath == GetConfigFileName() {
					log.Printf("警告: 配置路径指向HTTP API配置文件，跳过重复保存")
				} else {
					err := SaveToXrayConfig(configPath, nil, &outboundConfig, nil)
					if err != nil {
						log.Printf("保存到Xray配置文件失败: %v", err)
					} else {
						log.Printf("成功保存出站 %s 到Xray配置文件", outboundConfig.Tag)
					}
				}
			}
		}

		if successCount > 0 {
			SendJSONResponse(w, true, fmt.Sprintf("成功添加%d个出站", successCount), lastResponse)
		} else {
			SendJSONResponse(w, false, "添加出站失败: "+lastError.Error(), nil)
		}
	}
}

func HandleRemoveOutbound() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("收到删除出站请求: %s %s", r.Method, r.URL.Path)

		if r.Method != http.MethodPost && r.Method != http.MethodDelete {
			log.Printf("错误的请求方法: %s, 期望: POST或DELETE", r.Method)
			http.Error(w, "只支持POST或DELETE方法", http.StatusMethodNotAllowed)
			return
		}

		// 读取请求体
		var request struct {
			Tag string `json:"tag"`
		}

		err := json.NewDecoder(r.Body).Decode(&request)
		if err != nil {
			log.Printf("解析请求失败: %v", err)
			SendJSONResponse(w, false, "解析请求失败: "+err.Error(), nil)
			return
		}

		if request.Tag == "" {
			log.Printf("缺少出站标签")
			SendJSONResponse(w, false, "缺少出站标签(tag)", nil)
			return
		}

		log.Printf("准备删除出站: %s", request.Tag)

		// 连接到API服务器
		conn, ctx, cleanup, err := ConnectToAPI(apiAddr, timeout)
		if err != nil {
			log.Printf("连接API服务器失败: %v", err)
			SendJSONResponse(w, false, "连接API服务器失败: "+err.Error(), nil)
			return
		}
		defer cleanup()

		// 删除出站
		client := handlerService.NewHandlerServiceClient(conn)
		req := &handlerService.RemoveOutboundRequest{
			Tag: request.Tag,
		}

		resp, err := client.RemoveOutbound(ctx, req)
		if err != nil {
			log.Printf("删除出站失败: %v", err)
			SendJSONResponse(w, false, "删除出站失败: "+err.Error(), nil)
			return
		}

		log.Printf("出站删除成功: %s", request.Tag)
		// 从配置中移除
		RemoveOutbound(request.Tag)

		// 如果启用了保存到官方配置
		if saveToConfig {
			// 检查configPath是否指向HTTP API自己的配置文件
			if configPath == GetConfigFileName() {
				log.Printf("警告: 配置路径指向HTTP API配置文件，跳过重复保存")
			} else {
				err := RemoveFromXrayConfig(configPath, "", request.Tag, "")
				if err != nil {
					log.Printf("从Xray配置文件移除出站失败: %v", err)
				} else {
					log.Printf("成功从Xray配置文件移除出站 %s", request.Tag)
				}
			}
		}

		SendJSONResponse(w, true, fmt.Sprintf("出站 %s 删除成功", request.Tag), resp)
	}
}

func HandleAddRules() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("收到添加规则请求: %s %s", r.Method, r.URL.Path)

		if r.Method != http.MethodPost {
			log.Printf("错误的请求方法: %s, 期望: POST", r.Method)
			http.Error(w, "只支持POST方法", http.StatusMethodNotAllowed)
			return
		}

		// 读取请求体
		body, _ := io.ReadAll(r.Body)
		log.Printf("收到请求体: %s", string(body))

		// 解析配置
		conf, err := jsonconf.DecodeJSONConfig(strings.NewReader(string(body)))
		if err != nil {
			log.Printf("配置解析失败: %v", err)
			SendJSONResponse(w, false, "配置解析失败: "+err.Error(), nil)
			return
		}

		if conf.RouterConfig == nil || len(conf.RouterConfig.RuleList) == 0 {
			log.Printf("没有有效的路由规则配置")
			SendJSONResponse(w, false, "没有有效的路由规则配置", nil)
			return
		}

		// 连接到API服务器
		conn, ctx, cleanup, err := ConnectToAPI(apiAddr, timeout)
		if err != nil {
			log.Printf("连接API服务器失败: %v", err)
			SendJSONResponse(w, false, "连接API服务器失败: "+err.Error(), nil)
			return
		}
		defer cleanup()

		// 添加规则
		client := routerService.NewRoutingServiceClient(conn)
		config, err := conf.RouterConfig.Build()
		if err != nil {
			log.Printf("构建路由配置失败: %v", err)
			SendJSONResponse(w, false, "构建路由配置失败: "+err.Error(), nil)
			return
		}

		tmsg := serial.ToTypedMessage(config)
		if tmsg == nil {
			log.Printf("转换配置到TypedMessage失败")
			SendJSONResponse(w, false, "转换配置到TypedMessage失败", nil)
			return
		}

		ra := &routerService.AddRuleRequest{
			Config:       tmsg,
			ShouldAppend: true, // 默认追加而不是替换
		}

		resp, err := client.AddRule(ctx, ra)
		if err != nil {
			log.Printf("添加规则失败: %v", err)
			SendJSONResponse(w, false, "添加规则失败: "+err.Error(), nil)
			return
		}

		log.Printf("规则添加成功")

		// 保存规则配置
		for i := range conf.RouterConfig.RuleList {
			// 解析规则内容
			var ruleData map[string]interface{}
			if err := json.Unmarshal(conf.RouterConfig.RuleList[i], &ruleData); err != nil {
				log.Printf("解析规则数据失败: %v", err)
				continue
			}

			ruleConfig := RuleConfig{
				Type: "field",
			}

			// 提取出站标签
			if tag, ok := ruleData["outboundTag"].(string); ok {
				ruleConfig.OutboundTag = tag
			}

			// 提取规则标签
			if tag, ok := ruleData["tag"].(string); ok {
				// 如果传入的是tag字段，使用它的值赋给ruleTag
				ruleConfig.RuleTag = tag
			} else if tag, ok := ruleData["ruleTag"].(string); ok { // 优先使用ruleTag字段
				ruleConfig.RuleTag = tag
			}

			// 提取入站标签
			if inboundTags, ok := ruleData["inboundTag"].([]interface{}); ok && len(inboundTags) > 0 {
				tags := make([]string, 0, len(inboundTags))
				for _, tag := range inboundTags {
					if t, ok := tag.(string); ok {
						tags = append(tags, t)
					}
				}
				if len(tags) > 0 {
					ruleConfig.InboundTag = tags
				}
			} else if inboundTag, ok := ruleData["inboundTag"].(string); ok && inboundTag != "" {
				// 处理单个字符串情况
				ruleConfig.InboundTag = []string{inboundTag}
			}

			// 提取域名
			if domains, ok := ruleData["domain"].([]interface{}); ok && len(domains) > 0 {
				domainList := make([]string, 0, len(domains))
				for _, domain := range domains {
					if d, ok := domain.(string); ok {
						domainList = append(domainList, d)
					}
				}
				if len(domainList) > 0 {
					ruleConfig.Domain = domainList
				}
			}

			// 提取IP
			if ips, ok := ruleData["ip"].([]interface{}); ok && len(ips) > 0 {
				ipList := make([]string, 0, len(ips))
				for _, ip := range ips {
					if i, ok := ip.(string); ok {
						ipList = append(ipList, i)
					}
				}
				if len(ipList) > 0 {
					ruleConfig.IP = ipList
				}
			}

			// 提取端口
			if port, ok := ruleData["port"].(string); ok {
				ruleConfig.Port = port
			}

			// 提取协议
			if protocols, ok := ruleData["protocol"].([]interface{}); ok && len(protocols) > 0 {
				protocolList := make([]string, 0, len(protocols))
				for _, protocol := range protocols {
					if p, ok := protocol.(string); ok {
						protocolList = append(protocolList, p)
					}
				}
				if len(protocolList) > 0 {
					ruleConfig.Protocol = protocolList
				}
			}

			// 提取网络
			if network, ok := ruleData["network"].(string); ok {
				ruleConfig.Network = network
			}

			// 提取域名策略
			if domainStrategy, ok := ruleData["domainStrategy"].(string); ok {
				ruleConfig.DomainStrategy = domainStrategy
			}

			// 保存到配置
			AddRule(ruleConfig)

			// 如果启用了保存到官方配置
			if saveToConfig {
				// 检查configPath是否指向HTTP API自己的配置文件
				if configPath == GetConfigFileName() {
					log.Printf("警告: 配置路径指向HTTP API配置文件，跳过重复保存")
				} else {
					err := SaveToXrayConfig(configPath, nil, nil, &ruleConfig)
					if err != nil {
						log.Printf("保存到Xray配置文件失败: %v", err)
					} else {
						log.Printf("成功保存规则 %s 到Xray配置文件", ruleConfig.RuleTag)
					}
				}
			}
		}

		SendJSONResponse(w, true, "规则添加成功", resp)
	}
}

func HandleRemoveRule() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("收到删除规则请求: %s %s", r.Method, r.URL.Path)

		if r.Method != http.MethodPost && r.Method != http.MethodDelete {
			log.Printf("错误的请求方法: %s, 期望: POST或DELETE", r.Method)
			http.Error(w, "只支持POST或DELETE方法", http.StatusMethodNotAllowed)
			return
		}

		// 读取请求体并解析为map以获取所有字段
		var requestMap map[string]interface{}
		err := json.NewDecoder(r.Body).Decode(&requestMap)
		if err != nil {
			log.Printf("解析请求失败: %v", err)
			SendJSONResponse(w, false, "解析请求失败: "+err.Error(), nil)
			return
		}

		// 记录完整请求内容
		log.Printf("接收到的请求内容: %v", requestMap)

		// 检查所有可能的字段名
		var ruleTagToUse string

		// 优先级: ruleTag > rule_tag > tag
		if tag, ok := requestMap["ruleTag"].(string); ok && tag != "" {
			ruleTagToUse = tag
		} else if tag, ok := requestMap["rule_tag"].(string); ok && tag != "" {
			ruleTagToUse = tag
		} else if tag, ok := requestMap["tag"].(string); ok && tag != "" {
			// 兼容旧格式
			ruleTagToUse = tag
		} else {
			log.Printf("缺少规则标签")
			SendJSONResponse(w, false, "缺少规则标签(需要提供ruleTag字段)", nil)
			return
		}

		log.Printf("使用规则标签: %s", ruleTagToUse)

		// 连接到API服务器
		conn, ctx, cleanup, err := ConnectToAPI(apiAddr, timeout)
		if err != nil {
			log.Printf("连接API服务器失败: %v", err)
			SendJSONResponse(w, false, "连接API服务器失败: "+err.Error(), nil)
			return
		}
		defer cleanup()

		// 删除规则
		client := routerService.NewRoutingServiceClient(conn)
		req := &routerService.RemoveRuleRequest{
			RuleTag: ruleTagToUse, // 使用Xray gRPC API需要的字段名
		}

		log.Printf("发送gRPC请求删除规则, RuleTag=%s", ruleTagToUse)
		resp, err := client.RemoveRule(ctx, req)
		if err != nil {
			log.Printf("删除规则失败: %v", err)
			SendJSONResponse(w, false, "删除规则失败: "+err.Error(), nil)
			return
		}

		log.Printf("规则删除成功: %s", ruleTagToUse)
		// 从配置中移除
		RemoveRule(ruleTagToUse)

		// 如果启用了保存到官方配置
		if saveToConfig {
			// 检查configPath是否指向HTTP API自己的配置文件
			if configPath == GetConfigFileName() {
				log.Printf("警告: 配置路径指向HTTP API配置文件，跳过重复保存")
			} else {
				err := RemoveFromXrayConfig(configPath, "", "", ruleTagToUse)
				if err != nil {
					log.Printf("从Xray配置文件移除规则失败: %v", err)
				} else {
					log.Printf("成功从Xray配置文件移除规则 %s", ruleTagToUse)
				}
			}
		}

		SendJSONResponse(w, true, fmt.Sprintf("规则 %s 删除成功", ruleTagToUse), resp)
	}
}

func HandleAddSingleRule() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("收到添加单个规则请求: %s %s", r.Method, r.URL.Path)

		if r.Method != http.MethodPost {
			log.Printf("错误的请求方法: %s, 期望: POST", r.Method)
			http.Error(w, "只支持POST方法", http.StatusMethodNotAllowed)
			return
		}

		// 读取请求体
		var request struct {
			Type           string   `json:"type"`
			OutboundTag    string   `json:"outboundTag"`
			InboundTag     string   `json:"inboundTag"`  // 单个标签
			InboundTags    []string `json:"inboundTags"` // 多个标签
			Domain         []string `json:"domain,omitempty"`
			IP             []string `json:"ip,omitempty"`
			Port           string   `json:"port,omitempty"`
			Network        string   `json:"network,omitempty"`
			Protocol       []string `json:"protocol,omitempty"`
			RuleTag        string   `json:"ruleTag,omitempty"`
			DomainStrategy string   `json:"domainStrategy,omitempty"`
		}

		err := json.NewDecoder(r.Body).Decode(&request)
		if err != nil {
			log.Printf("解析请求失败: %v", err)
			SendJSONResponse(w, false, "解析请求失败: "+err.Error(), nil)
			return
		}

		if request.OutboundTag == "" {
			log.Printf("缺少出站标签")
			SendJSONResponse(w, false, "缺少出站标签(outboundTag)", nil)
			return
		}

		// 构建路由规则
		ruleConfig := RuleConfig{
			Type:        "field", // 默认为field类型
			OutboundTag: request.OutboundTag,
			RuleTag:     request.RuleTag,
		}

		// 处理入站标签
		if request.InboundTag != "" {
			ruleConfig.InboundTag = []string{request.InboundTag}
		} else if len(request.InboundTags) > 0 {
			ruleConfig.InboundTag = request.InboundTags
		}

		// 复制其他字段
		if len(request.Domain) > 0 {
			ruleConfig.Domain = request.Domain
		}
		if len(request.IP) > 0 {
			ruleConfig.IP = request.IP
		}
		if request.Port != "" {
			ruleConfig.Port = request.Port
		}
		if request.Network != "" {
			ruleConfig.Network = request.Network
		}
		if len(request.Protocol) > 0 {
			ruleConfig.Protocol = request.Protocol
		}
		if request.DomainStrategy != "" {
			ruleConfig.DomainStrategy = request.DomainStrategy
		}

		// 连接到API服务器
		conn, ctx, cleanup, err := ConnectToAPI(apiAddr, timeout)
		if err != nil {
			log.Printf("连接API服务器失败: %v", err)
			SendJSONResponse(w, false, "连接API服务器失败: "+err.Error(), nil)
			return
		}
		defer cleanup()

		// 构建路由配置JSON - 使用正确的格式
		routingConfig := map[string]interface{}{
			"routing": map[string]interface{}{
				"domainStrategy": func() string {
					if request.DomainStrategy != "" {
						return request.DomainStrategy
					}
					return "IPIfNonMatch"
				}(),
				"rules": []interface{}{
					map[string]interface{}{
						"type":        "field",
						"outboundTag": request.OutboundTag,
					},
				},
			},
		}

		// 添加可选字段
		rule := routingConfig["routing"].(map[string]interface{})["rules"].([]interface{})[0].(map[string]interface{})

		// 处理入站标签 - 根据数量决定格式
		if len(ruleConfig.InboundTag) == 1 {
			rule["inboundTag"] = ruleConfig.InboundTag[0]
		} else if len(ruleConfig.InboundTag) > 1 {
			rule["inboundTag"] = ruleConfig.InboundTag
		}

		if request.RuleTag != "" {
			rule["ruleTag"] = request.RuleTag // 使用ruleTag字段
		}

		if len(request.Domain) > 0 {
			rule["domain"] = request.Domain
		}
		if len(request.IP) > 0 {
			rule["ip"] = request.IP
		}
		if request.Port != "" {
			rule["port"] = request.Port
		}
		if request.Network != "" {
			rule["network"] = request.Network
		}
		if len(request.Protocol) > 0 {
			rule["protocol"] = request.Protocol
		}

		// 转换为JSON字符串
		routingData, err := json.Marshal(routingConfig)
		if err != nil {
			log.Printf("序列化路由配置失败: %v", err)
			SendJSONResponse(w, false, "序列化路由配置失败: "+err.Error(), nil)
			return
		}

		log.Printf("构建的路由配置: %s", string(routingData))

		// 解析配置
		conf, err := jsonconf.DecodeJSONConfig(strings.NewReader(string(routingData)))
		if err != nil {
			log.Printf("解析路由配置失败: %v", err)
			SendJSONResponse(w, false, "解析路由配置失败: "+err.Error(), nil)
			return
		}

		if conf.RouterConfig == nil || len(conf.RouterConfig.RuleList) == 0 {
			log.Printf("没有有效的路由规则配置")
			SendJSONResponse(w, false, "没有有效的路由规则配置", nil)
			return
		}

		// 添加规则
		client := routerService.NewRoutingServiceClient(conn)
		config, err := conf.RouterConfig.Build()
		if err != nil {
			log.Printf("构建路由配置失败: %v", err)
			SendJSONResponse(w, false, "构建路由配置失败: "+err.Error(), nil)
			return
		}

		tmsg := serial.ToTypedMessage(config)
		if tmsg == nil {
			log.Printf("转换路由配置到TypedMessage失败")
			SendJSONResponse(w, false, "转换路由配置到TypedMessage失败", nil)
			return
		}

		ra := &routerService.AddRuleRequest{
			Config:       tmsg,
			ShouldAppend: true,
		}

		resp, err := client.AddRule(ctx, ra)
		if err != nil {
			log.Printf("添加规则失败: %v", err)
			SendJSONResponse(w, false, "添加规则失败: "+err.Error(), nil)
			return
		}

		log.Printf("规则已成功添加到Xray")

		// 保存到配置
		log.Printf("保存规则到本地配置: type=%s, outboundTag=%s, inboundTags=%v",
			ruleConfig.Type, ruleConfig.OutboundTag, ruleConfig.InboundTag)
		AddRule(ruleConfig)

		// 如果启用了保存到官方配置
		if saveToConfig {
			// 检查configPath是否指向HTTP API自己的配置文件
			if configPath == GetConfigFileName() {
				log.Printf("警告: 配置路径指向HTTP API配置文件，跳过重复保存")
			} else {
				err := SaveToXrayConfig(configPath, nil, nil, &ruleConfig)
				if err != nil {
					log.Printf("保存到Xray配置文件失败: %v", err)
				} else {
					log.Printf("成功保存规则 %s 到Xray配置文件", ruleConfig.RuleTag)
				}
			}
		}

		SendJSONResponse(w, true, "规则添加成功", resp)
	}
}

func HandleReload() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("收到重新加载配置请求: %s %s", r.Method, r.URL.Path)

		if r.Method != http.MethodPost {
			log.Printf("错误的请求方法: %s, 期望: POST", r.Method)
			http.Error(w, "只支持POST方法", http.StatusMethodNotAllowed)
			return
		}

		// 连接到API服务器
		conn, ctx, cleanup, err := ConnectToAPI(apiAddr, timeout)
		if err != nil {
			log.Printf("连接API服务器失败: %v", err)
			SendJSONResponse(w, false, "连接API服务器失败: "+err.Error(), nil)
			return
		}
		defer cleanup()

		// 创建客户端
		inboundClient := handlerService.NewHandlerServiceClient(conn)
		outboundClient := handlerService.NewHandlerServiceClient(conn)
		routerClient := routerService.NewRoutingServiceClient(conn)

		// 从配置文件加载配置
		configMutex.RLock()
		inbounds := globalConfig.Inbounds
		outbounds := globalConfig.Outbounds

		// 获取routing.rules中的规则
		var rulesFromRouting []interface{}
		if globalConfig.Routing != nil {
			if rules, ok := globalConfig.Routing["rules"].([]interface{}); ok {
				rulesFromRouting = rules
			}
		}

		// 如果routing.rules为空，则尝试从外层的Rules中转换
		if len(rulesFromRouting) == 0 && len(globalConfig.Rules) > 0 {
			log.Printf("从外层Rules转换规则到routing.rules: %d个规则", len(globalConfig.Rules))
			rulesFromRouting = make([]interface{}, 0, len(globalConfig.Rules))

			for _, rule := range globalConfig.Rules {
				ruleMap := map[string]interface{}{
					"type":        rule.Type,
					"outboundTag": rule.OutboundTag,
				}

				// 使用tag而不是ruleTag
				if rule.RuleTag != "" {
					ruleMap["tag"] = rule.RuleTag
				}

				// 处理inboundTag
				if len(rule.InboundTag) > 0 {
					if len(rule.InboundTag) == 1 {
						ruleMap["inboundTag"] = rule.InboundTag[0]
					} else {
						ruleMap["inboundTag"] = rule.InboundTag
					}
				}

				// 添加其他字段
				if len(rule.Domain) > 0 {
					ruleMap["domain"] = rule.Domain
				}
				if len(rule.IP) > 0 {
					ruleMap["ip"] = rule.IP
				}
				if rule.Port != "" {
					ruleMap["port"] = rule.Port
				}
				if rule.Network != "" {
					ruleMap["network"] = rule.Network
				}
				if len(rule.Protocol) > 0 {
					ruleMap["protocol"] = rule.Protocol
				}
				if rule.DomainStrategy != "" {
					ruleMap["domainStrategy"] = rule.DomainStrategy
				}

				rulesFromRouting = append(rulesFromRouting, ruleMap)
			}
		}
		configMutex.RUnlock()

		// 记录操作结果
		results := struct {
			Inbounds  []string `json:"inbounds"`
			Outbounds []string `json:"outbounds"`
			Rules     []string `json:"rules"`
			Errors    []string `json:"errors,omitempty"`
		}{
			Inbounds:  []string{},
			Outbounds: []string{},
			Rules:     []string{},
			Errors:    []string{},
		}

		// 处理入站
		for _, inbound := range inbounds {
			log.Printf("添加入站: %s", inbound.Tag)

			// 构建入站配置JSON
			inboundJSON := map[string]interface{}{
				"tag":      inbound.Tag,
				"port":     inbound.Port,
				"listen":   inbound.Listen,
				"protocol": inbound.Protocol,
				"settings": inbound.Settings,
			}

			inboundData, err := json.Marshal(map[string]interface{}{
				"inbounds": []interface{}{inboundJSON},
			})
			if err != nil {
				errMsg := fmt.Sprintf("序列化入站配置失败: %v", err)
				log.Printf(errMsg)
				results.Errors = append(results.Errors, errMsg)
				continue
			}

			// 解析配置
			conf, err := jsonconf.DecodeJSONConfig(strings.NewReader(string(inboundData)))
			if err != nil {
				errMsg := fmt.Sprintf("解析入站配置失败: %v", err)
				log.Printf(errMsg)
				results.Errors = append(results.Errors, errMsg)
				continue
			}

			if len(conf.InboundConfigs) == 0 {
				errMsg := fmt.Sprintf("入站 %s 没有有效配置", inbound.Tag)
				log.Printf(errMsg)
				results.Errors = append(results.Errors, errMsg)
				continue
			}

			// 构建入站对象
			in, err := conf.InboundConfigs[0].Build()
			if err != nil {
				errMsg := fmt.Sprintf("构建入站对象失败: %v", err)
				log.Printf(errMsg)
				results.Errors = append(results.Errors, errMsg)
				continue
			}

			// 添加入站
			req := &handlerService.AddInboundRequest{
				Inbound: in,
			}
			_, err = inboundClient.AddInbound(ctx, req)
			if err != nil {
				errMsg := fmt.Sprintf("添加入站 %s 失败: %v", inbound.Tag, err)
				log.Printf(errMsg)
				results.Errors = append(results.Errors, errMsg)
				continue
			}

			log.Printf("入站 %s 添加成功", inbound.Tag)
			results.Inbounds = append(results.Inbounds, inbound.Tag)
		}

		// 处理出站
		for _, outbound := range outbounds {
			log.Printf("添加出站: %s", outbound.Tag)

			// 构建出站配置JSON
			outboundJSON := map[string]interface{}{
				"tag":      outbound.Tag,
				"protocol": outbound.Protocol,
				"settings": outbound.Settings,
			}

			if outbound.StreamSettings != nil {
				outboundJSON["streamSettings"] = outbound.StreamSettings
			}

			outboundData, err := json.Marshal(map[string]interface{}{
				"outbounds": []interface{}{outboundJSON},
			})
			if err != nil {
				errMsg := fmt.Sprintf("序列化出站配置失败: %v", err)
				log.Printf(errMsg)
				results.Errors = append(results.Errors, errMsg)
				continue
			}

			// 解析配置
			conf, err := jsonconf.DecodeJSONConfig(strings.NewReader(string(outboundData)))
			if err != nil {
				errMsg := fmt.Sprintf("解析出站配置失败: %v", err)
				log.Printf(errMsg)
				results.Errors = append(results.Errors, errMsg)
				continue
			}

			if len(conf.OutboundConfigs) == 0 {
				errMsg := fmt.Sprintf("出站 %s 没有有效配置", outbound.Tag)
				log.Printf(errMsg)
				results.Errors = append(results.Errors, errMsg)
				continue
			}

			// 构建出站对象
			out, err := conf.OutboundConfigs[0].Build()
			if err != nil {
				errMsg := fmt.Sprintf("构建出站对象失败: %v", err)
				log.Printf(errMsg)
				results.Errors = append(results.Errors, errMsg)
				continue
			}

			// 添加出站
			req := &handlerService.AddOutboundRequest{
				Outbound: out,
			}
			_, err = outboundClient.AddOutbound(ctx, req)
			if err != nil {
				errMsg := fmt.Sprintf("添加出站 %s 失败: %v", outbound.Tag, err)
				log.Printf(errMsg)
				results.Errors = append(results.Errors, errMsg)
				continue
			}

			log.Printf("出站 %s 添加成功", outbound.Tag)
			results.Outbounds = append(results.Outbounds, outbound.Tag)
		}

		// 处理路由规则
		for _, ruleInterface := range rulesFromRouting {
			ruleMap, ok := ruleInterface.(map[string]interface{})
			if !ok {
				errMsg := "规则格式不正确"
				log.Printf(errMsg)
				results.Errors = append(results.Errors, errMsg)
				continue
			}

			// 获取规则标签
			ruleTag := ""
			if tag, ok := ruleMap["ruleTag"].(string); ok {
				ruleTag = tag
			} else if tag, ok := ruleMap["tag"].(string); ok {
				// 如果规则有tag字段而没有ruleTag字段，将其转换为ruleTag字段
				ruleTag = tag
				ruleMap["ruleTag"] = tag
				delete(ruleMap, "tag")
			}

			logTag := ruleTag
			if logTag == "" {
				logTag = "[无标签]"
			}

			log.Printf("添加规则: %s", logTag)

			// 构建完整的路由配置，使用与用户POST格式相同的结构
			routingConfig := map[string]interface{}{
				"routing": map[string]interface{}{
					"domainStrategy": "IPIfNonMatch", // 使用默认策略
					"rules":          []interface{}{ruleMap},
				},
			}

			routingData, err := json.Marshal(routingConfig)
			if err != nil {
				errMsg := fmt.Sprintf("序列化路由规则配置失败: %v", err)
				log.Printf(errMsg)
				results.Errors = append(results.Errors, errMsg)
				continue
			}

			// 解析配置
			conf, err := jsonconf.DecodeJSONConfig(strings.NewReader(string(routingData)))
			if err != nil {
				errMsg := fmt.Sprintf("解析路由规则配置失败: %v", err)
				log.Printf(errMsg)
				results.Errors = append(results.Errors, errMsg)
				continue
			}

			if conf.RouterConfig == nil || len(conf.RouterConfig.RuleList) == 0 {
				errMsg := fmt.Sprintf("规则 %s 没有有效配置", logTag)
				log.Printf(errMsg)
				results.Errors = append(results.Errors, errMsg)
				continue
			}

			// 构建路由对象
			router, err := conf.RouterConfig.Build()
			if err != nil {
				errMsg := fmt.Sprintf("构建路由对象失败: %v", err)
				log.Printf(errMsg)
				results.Errors = append(results.Errors, errMsg)
				continue
			}

			// 添加规则
			tmsg := serial.ToTypedMessage(router)
			if tmsg == nil {
				errMsg := "转换路由配置到TypedMessage失败"
				log.Printf(errMsg)
				results.Errors = append(results.Errors, errMsg)
				continue
			}

			req := &routerService.AddRuleRequest{
				Config:       tmsg,
				ShouldAppend: true,
			}
			_, err = routerClient.AddRule(ctx, req)
			if err != nil {
				errMsg := fmt.Sprintf("添加规则 %s 失败: %v", logTag, err)
				log.Printf(errMsg)
				results.Errors = append(results.Errors, errMsg)
				continue
			}

			log.Printf("规则 %s 添加成功", logTag)
			if ruleTag != "" {
				results.Rules = append(results.Rules, ruleTag)
			} else {
				results.Rules = append(results.Rules, fmt.Sprintf("rule-%d", len(results.Rules)+1))
			}
		}

		// 返回结果
		log.Printf("配置重新加载完成, 成功添加: 入站=%d, 出站=%d, 规则=%d, 错误=%d",
			len(results.Inbounds), len(results.Outbounds), len(results.Rules), len(results.Errors))
		SendJSONResponse(w, true, "配置重新加载完成", results)
	}
}

// 解析shadowsocks URI
func parseShadowsocksURI(uri string, tag string) (string, error) {
	log.Printf("开始解析SS链接: %s", uri)
	// Shadowsocks有多种URI格式:
	// 1. ss://BASE64(method:password)@host:port?plugin=...#remarks
	// 2. ss://BASE64(method:password@host:port)#remarks
	// 3. ss://method:password@host:port?plugin=...#remarks

	// 移除ss://前缀
	uri = strings.TrimPrefix(uri, "ss://")
	log.Printf("移除前缀后: %s", uri)

	var method, password, host string
	var port int
	var plugin, pluginOpts string

	// 尝试找到#标记的备注
	parts := strings.SplitN(uri, "#", 2)
	uri = parts[0]
	remarks := ""
	if len(parts) == 2 {
		remarks = parts[1]
		// URL解码备注
		var err error
		remarks, err = url.QueryUnescape(remarks)
		if err != nil {
			log.Printf("备注URL解码失败: %v", err)
		}
	}
	log.Printf("移除备注后: %s", uri)

	// 解析查询参数
	var queryString string
	if strings.Contains(uri, "?") {
		queryParts := strings.SplitN(uri, "?", 2)
		uri = queryParts[0]
		queryString = queryParts[1]
		log.Printf("查询参数: %s", queryString)

		// 解析查询参数
		query, err := url.ParseQuery(queryString)
		if err == nil {
			plugin = query.Get("plugin")
			if plugin != "" {
				// 如果插件参数格式是 plugin;config，提取插件选项
				pluginParts := strings.SplitN(plugin, ";", 2)
				if len(pluginParts) > 1 {
					plugin = pluginParts[0]
					pluginOpts = pluginParts[1]
				}
			}
		}
	}
	log.Printf("移除查询参数后: %s", uri)

	// 检查是否含有@符号，识别URI格式
	if strings.Contains(uri, "@") {
		log.Printf("检测到@符号，处理格式1或3")
		// 格式1或3: ss://BASE64(method:password)@host:port 或 ss://method:password@host:port
		atSplit := strings.SplitN(uri, "@", 2)
		userInfoPart := atSplit[0]
		serverPart := atSplit[1]
		log.Printf("用户信息部分: %s, 服务器部分: %s", userInfoPart, serverPart)

		// 检查是否是Base64编码
		isBase64 := true
		// 检查userInfoPart是否可能是Base64编码
		for _, c := range userInfoPart {
			if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=' || c == '-' || c == '_') {
				isBase64 = false
				break
			}
		}
		log.Printf("是否可能是Base64编码: %v", isBase64)

		if isBase64 {
			// 补齐Base64字符串以解决填充问题
			paddingNeeded := len(userInfoPart) % 4
			if paddingNeeded > 0 {
				userInfoPart += strings.Repeat("=", 4-paddingNeeded)
				log.Printf("补齐Base64填充后: %s", userInfoPart)
			}

			// 尝试Base64解码
			var decodedUserInfo []byte
			var err error

			// 尝试标准Base64
			decodedUserInfo, err = base64.StdEncoding.DecodeString(userInfoPart)
			if err != nil {
				log.Printf("标准Base64解码失败: %v", err)
				// 尝试URL安全的Base64
				decodedUserInfo, err = base64.URLEncoding.DecodeString(userInfoPart)
				if err != nil {
					log.Printf("URL安全Base64解码失败: %v", err)
					// 尝试RawURLEncoding (没有填充的URL安全Base64)
					decodedUserInfo, err = base64.RawURLEncoding.DecodeString(userInfoPart)
					if err != nil {
						log.Printf("RawURLBase64解码失败: %v", err)
						// 尝试RawStdEncoding (没有填充的标准Base64)
						decodedUserInfo, err = base64.RawStdEncoding.DecodeString(userInfoPart)
						if err != nil {
							log.Printf("RawStdBase64解码失败: %v", err)
							// 都失败了，可能不是Base64编码
							isBase64 = false
						}
					}
				}
			}

			if isBase64 && err == nil {
				// 解码成功，解析method:password
				userInfoStr := string(decodedUserInfo)
				log.Printf("Base64解码后的用户信息: %s", userInfoStr)
				userInfoParts := strings.SplitN(userInfoStr, ":", 2)
				if len(userInfoParts) == 2 {
					method = userInfoParts[0]
					password = userInfoParts[1]
					log.Printf("解析得到 method: %s, password: %s", method, password)
				} else {
					log.Printf("Base64解码后的用户信息格式无效: %s", userInfoStr)
					return "", fmt.Errorf("Base64解码后的无效用户信息格式: %s", userInfoStr)
				}
			} else {
				log.Printf("Base64解码失败，尝试直接解析")
				isBase64 = false
			}
		}

		// 如果不是Base64编码或解码失败，直接解析
		if !isBase64 {
			userInfoParts := strings.SplitN(userInfoPart, ":", 2)
			if len(userInfoParts) == 2 {
				method = userInfoParts[0]
				password = userInfoParts[1]
				log.Printf("直接解析得到 method: %s, password: %s", method, password)
			} else {
				log.Printf("用户信息部分格式无效: %s", userInfoPart)
				return "", fmt.Errorf("无效的用户信息格式: %s", userInfoPart)
			}
		}

		// 解析服务器部分 host:port
		serverParts := strings.SplitN(serverPart, ":", 2)
		if len(serverParts) != 2 {
			log.Printf("服务器信息格式无效: %s", serverPart)
			return "", fmt.Errorf("无效的服务器信息格式: %s", serverPart)
		}
		host = serverParts[0]
		var parseErr error
		port, parseErr = strconv.Atoi(serverParts[1])
		if parseErr != nil || port <= 0 || port > 65535 {
			log.Printf("端口无效: %s, 错误: %v", serverParts[1], parseErr)
			return "", fmt.Errorf("无效的端口: %v", serverParts[1])
		}
		log.Printf("解析得到 host: %s, port: %d", host, port)
	} else {
		log.Printf("未检测到@符号，处理格式2")
		// 格式2: ss://BASE64(method:password@host:port)

		// 补齐Base64字符串以解决填充问题
		paddingNeeded := len(uri) % 4
		if paddingNeeded > 0 {
			uri += strings.Repeat("=", 4-paddingNeeded)
			log.Printf("补齐Base64填充后: %s", uri)
		}

		// 尝试多种Base64解码方式
		var data []byte
		var err error
		var decoded bool = false

		// 尝试所有可能的Base64解码方式
		decoders := []struct {
			name    string
			decoder *base64.Encoding
		}{
			{"StdEncoding", base64.StdEncoding},
			{"URLEncoding", base64.URLEncoding},
			{"RawURLEncoding", base64.RawURLEncoding},
			{"RawStdEncoding", base64.RawStdEncoding},
		}

		for _, decoder := range decoders {
			data, err = decoder.decoder.DecodeString(uri)
			if err == nil {
				log.Printf("使用 %s 成功解码", decoder.name)
				decoded = true
				break
			} else {
				log.Printf("使用 %s 解码失败: %v", decoder.name, err)
			}
		}

		if !decoded {
			log.Printf("所有Base64解码方式都失败")
			return "", fmt.Errorf("Base64解码失败: %v", err)
		}

		// 解析为 method:password@host:port 格式
		decodedStr := string(data)
		log.Printf("Base64解码后: %s", decodedStr)
		if !strings.Contains(decodedStr, "@") {
			log.Printf("解码后的字符串不包含@符号: %s", decodedStr)
			return "", fmt.Errorf("无效的Shadowsocks URI格式: 解码后未找到@符号")
		}

		atSplit := strings.SplitN(decodedStr, "@", 2)
		if len(atSplit) != 2 {
			log.Printf("解码后@分割失败: %s", decodedStr)
			return "", fmt.Errorf("无效的Shadowsocks URI格式: @分割后格式错误")
		}

		// 分解method:password部分
		userInfoParts := strings.SplitN(atSplit[0], ":", 2)
		if len(userInfoParts) != 2 {
			log.Printf("用户信息部分格式无效: %s", atSplit[0])
			return "", fmt.Errorf("无效的用户信息格式: %s", atSplit[0])
		}
		method = userInfoParts[0]
		password = userInfoParts[1]
		log.Printf("解析得到 method: %s, password: %s", method, password)

		// 分解host:port部分
		serverParts := strings.SplitN(atSplit[1], ":", 2)
		if len(serverParts) != 2 {
			log.Printf("服务器信息格式无效: %s", atSplit[1])
			return "", fmt.Errorf("无效的服务器信息格式: %s", atSplit[1])
		}
		host = serverParts[0]
		var parseErr error
		port, parseErr = strconv.Atoi(serverParts[1])
		if parseErr != nil || port <= 0 || port > 65535 {
			log.Printf("端口无效: %s, 错误: %v", serverParts[1], parseErr)
			return "", fmt.Errorf("无效的端口: %v", serverParts[1])
		}
		log.Printf("解析得到 host: %s, port: %d", host, port)
	}

	// 检查是否成功提取了所有必要参数
	if method == "" || password == "" || host == "" || port == 0 {
		log.Printf("缺少必要参数: method=%s, password=%s, host=%s, port=%d", method, password, host, port)
		return "", fmt.Errorf("缺少必要参数: method=%s, password=%s, host=%s, port=%d", method, password, host, port)
	}

	// 如果没有指定备注，使用主机名作为备注
	if remarks == "" {
		remarks = host
	}
	log.Printf("最终备注: %s", remarks)

	// 构建outbound配置
	var outboundJSON string

	if plugin == "" {
		// 无插件的基本配置
		outboundJSON = fmt.Sprintf(`{
			"outbounds": [
				{
					"protocol": "shadowsocks",
					"settings": {
						"servers": [
							{
								"address": "%s",
								"port": %d,
								"method": "%s",
								"password": "%s"
							}
						]
					},
					"tag": "%s"
				}
			]
		}`, host, port, method, password, tag)
	} else {
		// 带插件的配置
		pluginConfig := ""
		if plugin == "obfs-local" || plugin == "obfs" {
			// obfs插件配置转换为Xray的obfs设置
			pluginConfig = fmt.Sprintf(`
			"streamSettings": {
				"network": "tcp",
				"security": "",
				"tcpSettings": {
					"header": {
						"type": "http",
						"request": {
							"version": "1.1",
							"method": "GET",
							"path": ["/"],
							"headers": {
								"Host": ["%s"],
								"User-Agent": ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36"],
								"Accept-Encoding": ["gzip, deflate"],
								"Connection": ["keep-alive"],
								"Pragma": "no-cache"
							}
						}
					}
				}
			}`, host)
		} else {
			// 其他插件暂不支持，添加注释
			pluginConfig = fmt.Sprintf(`
			"_pluginInfo": {
				"plugin": "%s",
				"pluginOpts": "%s"
			}`, plugin, pluginOpts)
		}

		outboundJSON = fmt.Sprintf(`{
			"outbounds": [
				{
					"protocol": "shadowsocks",
					"settings": {
						"servers": [
							{
								"address": "%s",
								"port": %d,
								"method": "%s",
								"password": "%s"
							}
						]
					},
					"tag": "%s",
					%s
				}
			]
		}`, host, port, method, password, tag, pluginConfig)
	}

	log.Printf("生成出站配置成功")
	return outboundJSON, nil
}

// 解析socks URI
func parseSocksURI(uri string, tag string) (string, error) {
	// socks链接格式: socks://[username:password@]host:port#remarks
	u, err := url.Parse(uri)
	if err != nil {
		return "", fmt.Errorf("URL解析失败: %v", err)
	}

	if u.Scheme != "socks" {
		return "", fmt.Errorf("不是有效的socks链接")
	}

	// 获取必要参数
	server := u.Hostname()
	if server == "" {
		return "", fmt.Errorf("未指定服务器地址")
	}

	port, err := strconv.Atoi(u.Port())
	if err != nil || port <= 0 || port > 65535 {
		return "", fmt.Errorf("无效的端口: %v", u.Port())
	}

	// 获取用户名和密码（如果有）
	var username, password string
	if u.User != nil {
		username = u.User.Username()
		password, _ = u.User.Password()
	}

	// 获取备注
	remark := u.Fragment
	if remark == "" {
		remark = server
	}

	// 构建outbound配置
	var outboundJSON string
	if username != "" && password != "" {
		// 有认证信息
		outboundJSON = fmt.Sprintf(`{
			"outbounds": [
				{
					"protocol": "socks",
					"settings": {
						"servers": [
							{
								"address": "%s",
								"port": %d,
								"users": [
									{
										"user": "%s",
										"pass": "%s"
									}
								]
							}
						]
					},
					"tag": "%s"
				}
			]
		}`, server, port, username, password, tag)
	} else {
		// 无认证信息
		outboundJSON = fmt.Sprintf(`{
			"outbounds": [
				{
					"protocol": "socks",
					"settings": {
						"servers": [
							{
								"address": "%s",
								"port": %d
							}
						]
					},
					"tag": "%s"
				}
			]
		}`, server, port, tag)
	}

	return outboundJSON, nil
}

// 解析socks链接并生成入站配置
func parseSocksInboundURI(uri string, tag string) (string, error) {
	log.Printf("开始解析Socks入站链接: %s", uri)
	// socks链接格式: socks://[username:password@]host:port#remarks
	u, err := url.Parse(uri)
	if err != nil {
		return "", fmt.Errorf("URL解析失败: %v", err)
	}

	if u.Scheme != "socks" {
		return "", fmt.Errorf("不是有效的socks链接")
	}

	// 获取端口
	port, err := strconv.Atoi(u.Port())
	if err != nil || port <= 0 || port > 65535 {
		return "", fmt.Errorf("无效的端口: %v", u.Port())
	}

	// 获取主机
	host := u.Hostname()
	if host == "" {
		host = "0.0.0.0" // 默认绑定所有接口
	}

	// 获取用户名和密码（如果有）
	var auth bool = false
	var username, password string
	if u.User != nil {
		auth = true
		username = u.User.Username()
		password, _ = u.User.Password()
	}

	// 获取备注
	remark := u.Fragment
	if remark == "" {
		remark = fmt.Sprintf("socks-%d", port)
	}

	// 构建入站配置
	var configJSON string
	if auth {
		// 有认证信息
		configJSON = fmt.Sprintf(`{
			"inbounds": [
				{
					"port": %d,
					"protocol": "socks",
					"listen": "%s",
					"settings": {
						"auth": "password",
						"accounts": [
							{
								"user": "%s",
								"pass": "%s"
							}
						],
						"udp": true,
						"ip": "127.0.0.1"
					},
					"tag": "%s"
				}
			]
		}`, port, host, username, password, tag)
	} else {
		// 无认证信息
		configJSON = fmt.Sprintf(`{
			"inbounds": [
				{
					"port": %d,
					"protocol": "socks",
					"listen": "%s",
					"settings": {
						"auth": "noauth",
						"udp": true,
						"ip": "127.0.0.1"
					},
					"tag": "%s"
				}
			]
		}`, port, host, tag)
	}

	log.Printf("生成的入站配置: %s", configJSON)
	return configJSON, nil
}
