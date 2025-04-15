package httpapi

import (
	"encoding/json"
	"log"
	"os"
	"sync"
)

// 服务器配置结构
type ServerConfig struct {
	Inbounds  []InboundConfig        `json:"inbounds,omitempty"`
	Outbounds []OutboundConfig       `json:"outbounds,omitempty"`
	Rules     []RuleConfig           `json:"rules,omitempty"`
	Routing   map[string]interface{} `json:"routing,omitempty"`
}

// 入站配置
type InboundConfig struct {
	Tag      string                 `json:"tag"`
	Port     int                    `json:"port"`
	Listen   string                 `json:"listen"`
	Protocol string                 `json:"protocol"`
	Settings map[string]interface{} `json:"settings,omitempty"`
}

// 出站配置
type OutboundConfig struct {
	Tag            string                 `json:"tag"`
	Protocol       string                 `json:"protocol"`
	Settings       map[string]interface{} `json:"settings,omitempty"`
	Address        string                 `json:"address,omitempty"`
	Port           int                    `json:"port,omitempty"`
	StreamSettings map[string]interface{} `json:"streamSettings,omitempty"`
}

// 路由规则配置
type RuleConfig struct {
	Type           string   `json:"type"`
	InboundTag     []string `json:"inboundTag,omitempty"`
	OutboundTag    string   `json:"outboundTag,omitempty"`
	Domain         []string `json:"domain,omitempty"`
	IP             []string `json:"ip,omitempty"`
	Port           string   `json:"port,omitempty"`
	Network        string   `json:"network,omitempty"`
	Protocol       []string `json:"protocol,omitempty"`
	RuleTag        string   `json:"ruleTag,omitempty"`
	DomainStrategy string   `json:"domainStrategy,omitempty"`
}

// 全局配置对象和锁
var (
	globalConfig ServerConfig
	configMutex  sync.RWMutex
)

// 加载或创建配置文件
func InitConfig() {
	// 检查配置文件是否存在是的
	if _, err := os.Stat(GetConfigFileName()); os.IsNotExist(err) {
		// 文件不存在，创建默认配置
		defaultConfig := &ServerConfig{
			Inbounds:  []InboundConfig{},
			Outbounds: []OutboundConfig{},
			Rules:     []RuleConfig{},
			Routing:   map[string]interface{}{"domainStrategy": "IPIfNonMatch", "rules": []interface{}{}},
		}

		// 将配置保存到文件
		data, err := json.MarshalIndent(defaultConfig, "", "    ")
		if err != nil {
			log.Printf("创建默认配置失败: %v", err)
			return
		}

		if err := os.WriteFile(GetConfigFileName(), data, 0644); err != nil {
			log.Printf("保存默认配置失败: %v", err)
			return
		}

		log.Printf("已创建默认配置文件: %s", GetConfigFileName())
		globalConfig = *defaultConfig
	} else {
		// 文件存在，加载配置
		data, err := os.ReadFile(GetConfigFileName())
		if err != nil {
			log.Printf("读取配置文件失败: %v", err)
			return
		}

		var config ServerConfig
		if err := json.Unmarshal(data, &config); err != nil {
			log.Printf("解析配置文件失败: %v", err)
			return
		}

		log.Printf("已加载配置文件: %s", GetConfigFileName())
		globalConfig = config

		// 确保Routing对象存在
		if globalConfig.Routing == nil {
			globalConfig.Routing = map[string]interface{}{
				"domainStrategy": "IPIfNonMatch",
				"rules":          []interface{}{},
			}
		}
	}
}

// 保存配置到文件
func SaveConfig() error {
	// 确保routing对象中包含正确的规则
	if globalConfig.Routing == nil {
		globalConfig.Routing = map[string]interface{}{
			"domainStrategy": "IPIfNonMatch",
			"rules":          []interface{}{},
		}
	}

	// 确保domainStrategy字段存在
	if _, ok := globalConfig.Routing["domainStrategy"]; !ok {
		globalConfig.Routing["domainStrategy"] = "IPIfNonMatch"
	}

	// 将外层的Rules转移到routing.rules中
	routingRules, ok := globalConfig.Routing["rules"].([]interface{})
	if !ok {
		routingRules = []interface{}{}
	}

	// 检查并添加外层Rules中的规则到routing.rules
	for _, rule := range globalConfig.Rules {
		// 先检查规则是否已经存在于routing.rules中
		found := false
		for _, existingRule := range routingRules {
			if existingRuleMap, ok := existingRule.(map[string]interface{}); ok {
				if tag, ok := existingRuleMap["ruleTag"].(string); ok &&
					rule.RuleTag != "" && tag == rule.RuleTag {
					found = true
					break
				} else if tag, ok := existingRuleMap["tag"].(string); ok &&
					rule.RuleTag != "" && tag == rule.RuleTag {
					found = true
					break
				}
			}
		}

		// 如果不存在，则添加
		if !found {
			ruleMap := map[string]interface{}{
				"type":        rule.Type,
				"outboundTag": rule.OutboundTag,
			}

			// 统一使用ruleTag字段
			if rule.RuleTag != "" {
				ruleMap["ruleTag"] = rule.RuleTag
			}

			// 处理入站标签
			if len(rule.InboundTag) > 0 {
				if len(rule.InboundTag) == 1 {
					// 如果只有一个入站标签，使用字符串格式
					ruleMap["inboundTag"] = rule.InboundTag[0]
				} else {
					// 多个入站标签，使用数组格式
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

			routingRules = append(routingRules, ruleMap)
		}
	}

	// 统一将所有规则中的tag字段转换为ruleTag
	for i, rule := range routingRules {
		if ruleMap, ok := rule.(map[string]interface{}); ok {
			// 如果有tag字段，但没有ruleTag字段，将tag转换为ruleTag
			if tag, ok := ruleMap["tag"].(string); ok {
				if _, hasRuleTag := ruleMap["ruleTag"].(string); !hasRuleTag {
					ruleMap["ruleTag"] = tag
					delete(ruleMap, "tag")
					routingRules[i] = ruleMap
				}
			}
		}
	}

	// 更新routing.rules
	globalConfig.Routing["rules"] = routingRules

	// 清空外层Rules以防止重复
	// globalConfig.Rules = []RuleConfig{}
	// 注意：暂时保留外层Rules以保持向后兼容，但在实际写入JSON时会忽略它

	// 创建一个可序列化的配置对象，不包含外层的Rules
	serializableConfig := struct {
		Inbounds  []InboundConfig        `json:"inbounds,omitempty"`
		Outbounds []OutboundConfig       `json:"outbounds,omitempty"`
		Routing   map[string]interface{} `json:"routing,omitempty"`
	}{
		Inbounds:  globalConfig.Inbounds,
		Outbounds: globalConfig.Outbounds,
		Routing:   globalConfig.Routing,
	}

	data, err := json.MarshalIndent(serializableConfig, "", "    ")
	if err != nil {
		return err
	}

	return os.WriteFile(GetConfigFileName(), data, 0644)
}

// 添加入站配置
func AddInbound(inbound InboundConfig) {
	configMutex.Lock()
	defer configMutex.Unlock()

	// 检查是否已存在同标签入站
	for i, existing := range globalConfig.Inbounds {
		if existing.Tag == inbound.Tag {
			// 更新现有入站
			globalConfig.Inbounds[i] = inbound
			SaveConfig()
			return
		}
	}

	// 添加新入站
	globalConfig.Inbounds = append(globalConfig.Inbounds, inbound)
	SaveConfig()
}

// 移除入站配置
func RemoveInbound(tag string) bool {
	configMutex.Lock()
	defer configMutex.Unlock()

	for i, inbound := range globalConfig.Inbounds {
		if inbound.Tag == tag {
			// 移除入站
			globalConfig.Inbounds = append(globalConfig.Inbounds[:i], globalConfig.Inbounds[i+1:]...)
			SaveConfig()
			return true
		}
	}

	return false
}

// 添加出站配置
func AddOutbound(outbound OutboundConfig) {
	configMutex.Lock()
	defer configMutex.Unlock()

	// 检查是否已存在同标签出站
	for i, existing := range globalConfig.Outbounds {
		if existing.Tag == outbound.Tag {
			// 更新现有出站
			globalConfig.Outbounds[i] = outbound
			SaveConfig()
			return
		}
	}

	// 添加新出站
	globalConfig.Outbounds = append(globalConfig.Outbounds, outbound)
	SaveConfig()
}

// 移除出站配置
func RemoveOutbound(tag string) bool {
	configMutex.Lock()
	defer configMutex.Unlock()

	for i, outbound := range globalConfig.Outbounds {
		if outbound.Tag == tag {
			// 移除出站
			globalConfig.Outbounds = append(globalConfig.Outbounds[:i], globalConfig.Outbounds[i+1:]...)
			SaveConfig()
			return true
		}
	}

	return false
}

// 添加路由规则
func AddRule(rule RuleConfig) {
	configMutex.Lock()
	defer configMutex.Unlock()

	// 处理routing对象和rules数组
	if globalConfig.Routing == nil {
		globalConfig.Routing = map[string]interface{}{
			"domainStrategy": "IPIfNonMatch",
			"rules":          []interface{}{},
		}
	}

	// 确保routing.rules数组存在
	rules, ok := globalConfig.Routing["rules"].([]interface{})
	if !ok {
		rules = []interface{}{}
		globalConfig.Routing["rules"] = rules
	}

	// 构建规则对象
	ruleMap := map[string]interface{}{
		"type":        rule.Type,
		"outboundTag": rule.OutboundTag,
	}

	// 统一使用ruleTag字段
	if rule.RuleTag != "" {
		ruleMap["ruleTag"] = rule.RuleTag
	}

	// 处理入站标签
	if len(rule.InboundTag) > 0 {
		if len(rule.InboundTag) == 1 {
			// 如果只有一个入站标签，使用字符串格式
			ruleMap["inboundTag"] = rule.InboundTag[0]
		} else {
			// 多个入站标签，使用数组格式
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

	// 找到并更新或添加规则
	found := false
	if rule.RuleTag != "" {
		// 检查是否已存在同标签规则（在routing.rules中）
		routingRules, ok := globalConfig.Routing["rules"].([]interface{})
		if ok {
			for i, existingRule := range routingRules {
				if existingRuleMap, ok := existingRule.(map[string]interface{}); ok {
					if tag, ok := existingRuleMap["ruleTag"].(string); ok && tag == rule.RuleTag {
						// 更新现有规则
						routingRules[i] = ruleMap
						found = true
						break
					} else if tag, ok := existingRuleMap["tag"].(string); ok && tag == rule.RuleTag {
						// 兼容性处理，如果找到旧的tag字段，也更新
						routingRules[i] = ruleMap
						found = true
						break
					}
				}
			}
		}

		// 如果未找到，添加到routing.rules
		if !found {
			routingRules = append(routingRules, ruleMap)
			globalConfig.Routing["rules"] = routingRules
		}

		// 同时检查老式的外层rules数组，保证兼容性
		for i, existing := range globalConfig.Rules {
			if existing.RuleTag == rule.RuleTag {
				// 更新现有规则（外层）以保持兼容
				globalConfig.Rules[i] = rule
				found = true
				break
			}
		}
	}

	// 如果未找到，同时添加到外层rules以保持兼容
	if !found {
		globalConfig.Rules = append(globalConfig.Rules, rule)
	}

	// 确保routing中有domainStrategy
	if _, ok := globalConfig.Routing["domainStrategy"]; !ok {
		globalConfig.Routing["domainStrategy"] = "IPIfNonMatch"
	}

	SaveConfig()
}

// 移除路由规则
func RemoveRule(ruleTag string) bool {
	configMutex.Lock()
	defer configMutex.Unlock()

	removed := false

	// 从routing.rules中移除
	if globalConfig.Routing != nil {
		if rules, ok := globalConfig.Routing["rules"].([]interface{}); ok {
			newRules := make([]interface{}, 0, len(rules))
			for _, rule := range rules {
				if ruleMap, ok := rule.(map[string]interface{}); ok {
					// 检查ruleTag字段
					if tag, ok := ruleMap["ruleTag"].(string); !ok || tag != ruleTag {
						// 如果没有ruleTag字段或者不匹配，检查tag字段（兼容性）
						if tag, ok := ruleMap["tag"].(string); !ok || tag != ruleTag {
							newRules = append(newRules, rule)
						} else {
							removed = true
						}
					} else {
						removed = true
					}
				} else {
					newRules = append(newRules, rule)
				}
			}
			globalConfig.Routing["rules"] = newRules
		}
	}

	// 同时也从外层rules中移除（兼容性）
	for i, rule := range globalConfig.Rules {
		if rule.RuleTag == ruleTag {
			// 移除规则
			globalConfig.Rules = append(globalConfig.Rules[:i], globalConfig.Rules[i+1:]...)
			removed = true
			break
		}
	}

	if removed {
		SaveConfig()
	}

	return removed
}

// 获取入站配置
func GetInbounds() []InboundConfig {
	configMutex.RLock()
	defer configMutex.RUnlock()

	// 返回副本避免并发问题
	result := make([]InboundConfig, len(globalConfig.Inbounds))
	copy(result, globalConfig.Inbounds)
	return result
}

// 获取出站配置
func GetOutbounds() []OutboundConfig {
	configMutex.RLock()
	defer configMutex.RUnlock()

	// 返回副本避免并发问题
	result := make([]OutboundConfig, len(globalConfig.Outbounds))
	copy(result, globalConfig.Outbounds)
	return result
}

// 获取路由规则
func GetRules() []RuleConfig {
	configMutex.RLock()
	defer configMutex.RUnlock()

	// 返回副本避免并发问题
	result := make([]RuleConfig, len(globalConfig.Rules))
	copy(result, globalConfig.Rules)
	return result
}

// 保存到Xray配置文件
func SaveToXrayConfig(configPath string, inbound *InboundConfig, outbound *OutboundConfig, rule *RuleConfig) error {
	// 读取现有配置
	configData, err := os.ReadFile(configPath)
	if err != nil {
		log.Printf("读取Xray配置文件失败: %v", err)
		return err
	}

	var xrayConfig map[string]interface{}
	if err := json.Unmarshal(configData, &xrayConfig); err != nil {
		log.Printf("解析Xray配置文件失败: %v", err)
		return err
	}

	// 更新配置
	if inbound != nil {
		// 添加入站
		inbounds, ok := xrayConfig["inbounds"].([]interface{})
		if !ok {
			inbounds = []interface{}{}
		}

		// 转换为map添加
		inboundMap := map[string]interface{}{
			"tag":      inbound.Tag,
			"port":     inbound.Port,
			"listen":   inbound.Listen,
			"protocol": inbound.Protocol,
			"settings": inbound.Settings,
		}

		// 检查同名入站，更新或添加
		found := false
		for i, item := range inbounds {
			if ib, ok := item.(map[string]interface{}); ok {
				if tag, ok := ib["tag"].(string); ok && tag == inbound.Tag {
					inbounds[i] = inboundMap
					found = true
					break
				}
			}
		}

		if !found {
			inbounds = append(inbounds, inboundMap)
		}

		xrayConfig["inbounds"] = inbounds
	}

	if outbound != nil {
		// 添加出站
		outbounds, ok := xrayConfig["outbounds"].([]interface{})
		if !ok {
			outbounds = []interface{}{}
		}

		// 转换为map添加
		outboundMap := map[string]interface{}{
			"tag":      outbound.Tag,
			"protocol": outbound.Protocol,
			"settings": outbound.Settings,
		}

		if outbound.StreamSettings != nil {
			outboundMap["streamSettings"] = outbound.StreamSettings
		}

		// 检查同名出站，更新或添加
		found := false
		for i, item := range outbounds {
			if ob, ok := item.(map[string]interface{}); ok {
				if tag, ok := ob["tag"].(string); ok && tag == outbound.Tag {
					outbounds[i] = outboundMap
					found = true
					break
				}
			}
		}

		if !found {
			outbounds = append(outbounds, outboundMap)
		}

		xrayConfig["outbounds"] = outbounds
	}

	if rule != nil {
		// 确保routing对象存在
		routing, ok := xrayConfig["routing"].(map[string]interface{})
		if !ok {
			routing = map[string]interface{}{
				"domainStrategy": "IPIfNonMatch", // 默认策略
				"rules":          []interface{}{},
			}
			xrayConfig["routing"] = routing
		}

		// 确保domainStrategy存在
		if _, ok := routing["domainStrategy"]; !ok {
			routing["domainStrategy"] = "IPIfNonMatch"
		}

		// 确保rules数组存在
		rules, ok := routing["rules"].([]interface{})
		if !ok {
			rules = []interface{}{}
			routing["rules"] = rules
		}

		// 转换为map添加
		ruleMap := map[string]interface{}{
			"type":        rule.Type,
			"outboundTag": rule.OutboundTag,
		}

		// 统一使用ruleTag字段，去掉tag字段
		if rule.RuleTag != "" {
			ruleMap["ruleTag"] = rule.RuleTag
		}

		// 处理入站标签
		if len(rule.InboundTag) > 0 {
			if len(rule.InboundTag) == 1 {
				// 如果只有一个入站标签，使用字符串格式
				ruleMap["inboundTag"] = rule.InboundTag[0]
			} else {
				// 多个入站标签，使用数组格式
				ruleMap["inboundTag"] = rule.InboundTag
			}
		}

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

		// 添加域名策略
		if rule.DomainStrategy != "" {
			ruleMap["domainStrategy"] = rule.DomainStrategy
		}

		// 检查同名规则，更新或添加
		found := false
		for i, item := range rules {
			if r, ok := item.(map[string]interface{}); ok {
				// 使用ruleTag字段进行匹配
				if tag, ok := r["ruleTag"].(string); ok && tag == rule.RuleTag && rule.RuleTag != "" {
					rules[i] = ruleMap
					found = true
					break
				} else if tag, ok := r["tag"].(string); ok && tag == rule.RuleTag && rule.RuleTag != "" {
					// 兼容性处理：如果找到旧的tag字段匹配，也更新
					rules[i] = ruleMap
					found = true
					break
				}
			}
		}

		if !found {
			rules = append(rules, ruleMap)
		}

		routing["rules"] = rules
		xrayConfig["routing"] = routing

		// 删除外层的rules数组（如果存在）
		delete(xrayConfig, "rules")
	}

	// 写回文件
	updatedData, err := json.MarshalIndent(xrayConfig, "", "    ")
	if err != nil {
		log.Printf("序列化Xray配置失败: %v", err)
		return err
	}

	return os.WriteFile(configPath, updatedData, 0644)
}

// 从Xray配置文件移除配置
func RemoveFromXrayConfig(configPath string, inboundTag, outboundTag, ruleTag string) error {
	// 读取现有配置
	configData, err := os.ReadFile(configPath)
	if err != nil {
		log.Printf("读取Xray配置文件失败: %v", err)
		return err
	}

	var xrayConfig map[string]interface{}
	if err := json.Unmarshal(configData, &xrayConfig); err != nil {
		log.Printf("解析Xray配置文件失败: %v", err)
		return err
	}

	// 移除配置
	if inboundTag != "" {
		inbounds, ok := xrayConfig["inbounds"].([]interface{})
		if ok {
			newInbounds := make([]interface{}, 0, len(inbounds))
			for _, item := range inbounds {
				if ib, ok := item.(map[string]interface{}); ok {
					if tag, ok := ib["tag"].(string); !ok || tag != inboundTag {
						newInbounds = append(newInbounds, item)
					}
				} else {
					newInbounds = append(newInbounds, item)
				}
			}
			xrayConfig["inbounds"] = newInbounds
		}
	}

	if outboundTag != "" {
		outbounds, ok := xrayConfig["outbounds"].([]interface{})
		if ok {
			newOutbounds := make([]interface{}, 0, len(outbounds))
			for _, item := range outbounds {
				if ob, ok := item.(map[string]interface{}); ok {
					if tag, ok := ob["tag"].(string); !ok || tag != outboundTag {
						newOutbounds = append(newOutbounds, item)
					}
				} else {
					newOutbounds = append(newOutbounds, item)
				}
			}
			xrayConfig["outbounds"] = newOutbounds
		}
	}

	if ruleTag != "" {
		// 优先从routing.rules中移除
		routing, ok := xrayConfig["routing"].(map[string]interface{})
		if ok {
			rules, ok := routing["rules"].([]interface{})
			if ok {
				newRules := make([]interface{}, 0, len(rules))
				for _, item := range rules {
					if r, ok := item.(map[string]interface{}); ok {
						// 检查ruleTag字段
						if tag, ok := r["ruleTag"].(string); !ok || tag != ruleTag {
							// 如果不匹配，检查旧的tag字段（兼容性）
							if tag, ok := r["tag"].(string); !ok || tag != ruleTag {
								newRules = append(newRules, item)
							}
						}
					} else {
						newRules = append(newRules, item)
					}
				}
				routing["rules"] = newRules
				xrayConfig["routing"] = routing
			}
		}

		// 同时删除外层rules数组（如果存在）
		delete(xrayConfig, "rules")
	}

	// 写回文件
	updatedData, err := json.MarshalIndent(xrayConfig, "", "    ")
	if err != nil {
		log.Printf("序列化Xray配置失败: %v", err)
		return err
	}

	return os.WriteFile(configPath, updatedData, 0644)
}
