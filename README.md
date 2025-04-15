# Project X

[Project X](https://github.com/XTLS) originates from XTLS protocol, providing a set of network tools such as [Xray-core](https://github.com/XTLS/Xray-core) and [REALITY](https://github.com/XTLS/REALITY).

[README](https://github.com/XTLS/Xray-core#readme) is open, so feel free to submit your project [here](https://github.com/XTLS/Xray-core/pulls).

## Donation & NFTs

- **ETH/USDT/USDC: `0xDc3Fe44F0f25D13CACb1C4896CD0D321df3146Ee`**
- **Project X NFT: [Announcement of NFTs by Project X](https://github.com/XTLS/Xray-core/discussions/3633)**
- **REALITY NFT: [XHTTP: Beyond REALITY](https://github.com/XTLS/Xray-core/discussions/4113)**

## License

[Mozilla Public License Version 2.0](https://github.com/XTLS/Xray-core/blob/main/LICENSE)

## Documentation

[Project X Official Website](https://xtls.github.io)

## Telegram

[Project X](https://t.me/projectXray)

[Project X Channel](https://t.me/projectXtls)

[Project VLESS](https://t.me/projectVless) (Русский)

[Project XHTTP](https://t.me/projectXhttp) (Persian)

## Installation

- Linux Script
  - [XTLS/Xray-install](https://github.com/XTLS/Xray-install) (**Official**)
  - [tempest](https://github.com/team-cloudchaser/tempest) (supports [`systemd`](https://systemd.io) and [OpenRC](https://github.com/OpenRC/openrc); Linux-only)
- Docker
  - [ghcr.io/xtls/xray-core](https://ghcr.io/xtls/xray-core) (**Official**)
  - [teddysun/xray](https://hub.docker.com/r/teddysun/xray)
  - [wulabing/xray_docker](https://github.com/wulabing/xray_docker)
- Web Panel - **WARNING: Please DO NOT USE plain HTTP panels like 3X-UI**, as they are believed to be bribed by Iran GFW for supporting plain HTTP by default and refused to change (https://github.com/XTLS/Xray-core/pull/3884#issuecomment-2439595331), which has already put many users' data security in danger in the past few years. **If you are already using 3X-UI, please switch to the following panels, which are verified to support HTTPS and SSH port forwarding only:**
  - [Remnawave](https://github.com/remnawave/panel)
  - [Marzban](https://github.com/Gozargah/Marzban)
  - [Xray-UI](https://github.com/qist/xray-ui)
  - [Hiddify](https://github.com/hiddify/Hiddify-Manager)
- One Click
  - [Xray-REALITY](https://github.com/zxcvos/Xray-script), [xray-reality](https://github.com/sajjaddg/xray-reality), [reality-ezpz](https://github.com/aleskxyz/reality-ezpz)
  - [Xray_bash_onekey](https://github.com/hello-yunshu/Xray_bash_onekey), [XTool](https://github.com/LordPenguin666/XTool)
  - [v2ray-agent](https://github.com/mack-a/v2ray-agent), [Xray_onekey](https://github.com/wulabing/Xray_onekey), [ProxySU](https://github.com/proxysu/ProxySU)
- Magisk
  - [Xray4Magisk](https://github.com/Asterisk4Magisk/Xray4Magisk)
  - [Xray_For_Magisk](https://github.com/E7KMbb/Xray_For_Magisk)
- Homebrew
  - `brew install xray`

## Usage

- Example
  - [VLESS-XTLS-uTLS-REALITY](https://github.com/XTLS/REALITY#readme)
  - [VLESS-TCP-XTLS-Vision](https://github.com/XTLS/Xray-examples/tree/main/VLESS-TCP-XTLS-Vision)
  - [All-in-One-fallbacks-Nginx](https://github.com/XTLS/Xray-examples/tree/main/All-in-One-fallbacks-Nginx)
- Xray-examples
  - [XTLS/Xray-examples](https://github.com/XTLS/Xray-examples)
  - [chika0801/Xray-examples](https://github.com/chika0801/Xray-examples)
  - [lxhao61/integrated-examples](https://github.com/lxhao61/integrated-examples)
- Tutorial
  - [XTLS Vision](https://github.com/chika0801/Xray-install)
  - [REALITY (English)](https://cscot.pages.dev/2023/03/02/Xray-REALITY-tutorial/)
  - [XTLS-Iran-Reality (English)](https://github.com/SasukeFreestyle/XTLS-Iran-Reality)
  - [Xray REALITY with 'steal oneself' (English)](https://computerscot.github.io/vless-xtls-utls-reality-steal-oneself.html)
  - [Xray with WireGuard inbound (English)](https://g800.pages.dev/wireguard)

## GUI Clients

- OpenWrt
  - [PassWall](https://github.com/xiaorouji/openwrt-passwall), [PassWall 2](https://github.com/xiaorouji/openwrt-passwall2)
  - [ShadowSocksR Plus+](https://github.com/fw876/helloworld)
  - [luci-app-xray](https://github.com/yichya/luci-app-xray) ([openwrt-xray](https://github.com/yichya/openwrt-xray))
- Asuswrt-Merlin
  - [XRAYUI](https://github.com/DanielLavrushin/asuswrt-merlin-xrayui)
- Windows
  - [v2rayN](https://github.com/2dust/v2rayN)
  - [Furious](https://github.com/LorenEteval/Furious)
  - [Invisible Man - Xray](https://github.com/InvisibleManVPN/InvisibleMan-XRayClient)
- Android
  - [v2rayNG](https://github.com/2dust/v2rayNG)
  - [X-flutter](https://github.com/XTLS/X-flutter)
  - [SaeedDev94/Xray](https://github.com/SaeedDev94/Xray)
- iOS & macOS arm64
  - [Happ](https://apps.apple.com/app/happ-proxy-utility/id6504287215)
  - [FoXray](https://apps.apple.com/app/foxray/id6448898396)
  - [Streisand](https://apps.apple.com/app/streisand/id6450534064)
- macOS arm64 & x64
  - [V2rayU](https://github.com/yanue/V2rayU)
  - [V2RayXS](https://github.com/tzmax/V2RayXS)
  - [Furious](https://github.com/LorenEteval/Furious)
  - [FoXray](https://apps.apple.com/app/foxray/id6448898396)
- Linux
  - [v2rayA](https://github.com/v2rayA/v2rayA)
  - [Furious](https://github.com/LorenEteval/Furious)

## Others that support VLESS, XTLS, REALITY, XUDP, PLUX...

- iOS & macOS arm64
  - [Shadowrocket](https://apps.apple.com/app/shadowrocket/id932747118)
- Xray Tools
  - [xray-knife](https://github.com/lilendian0x00/xray-knife)
  - [xray-checker](https://github.com/kutovoys/xray-checker)
- Xray Wrapper
  - [XTLS/libXray](https://github.com/XTLS/libXray)
  - [xtlsapi](https://github.com/hiddify/xtlsapi)
  - [AndroidLibXrayLite](https://github.com/2dust/AndroidLibXrayLite)
  - [Xray-core-python](https://github.com/LorenEteval/Xray-core-python)
  - [xray-api](https://github.com/XVGuardian/xray-api)
- [XrayR](https://github.com/XrayR-project/XrayR)
  - [XrayR-release](https://github.com/XrayR-project/XrayR-release)
  - [XrayR-V2Board](https://github.com/missuo/XrayR-V2Board)
- [Clash.Meta](https://github.com/MetaCubeX/Clash.Meta)
  - [clashN](https://github.com/2dust/clashN)
  - [Clash Meta for Android](https://github.com/MetaCubeX/ClashMetaForAndroid)
- [sing-box](https://github.com/SagerNet/sing-box)

## Contributing

[Code of Conduct](https://github.com/XTLS/Xray-core/blob/main/CODE_OF_CONDUCT.md)

## Credits

- [Xray-core v1.0.0](https://github.com/XTLS/Xray-core/releases/tag/v1.0.0) was forked from [v2fly-core 9a03cc5](https://github.com/v2fly/v2ray-core/commit/9a03cc5c98d04cc28320fcee26dbc236b3291256), and we have made & accumulated a huge number of enhancements over time, check [the release notes for each version](https://github.com/XTLS/Xray-core/releases).
- For third-party projects used in [Xray-core](https://github.com/XTLS/Xray-core), check your local or [the latest go.mod](https://github.com/XTLS/Xray-core/blob/main/go.mod).

## One-line Compilation

### Windows (PowerShell)

```powershell
$env:CGO_ENABLED=0
go build -o xray.exe -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -v ./main
```

### Linux / macOS

```bash
CGO_ENABLED=0 go build -o xray -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -v ./main
```

### Reproducible Releases

Make sure that you are using the same Go version, and remember to set the git commit id (7 bytes):

```bash
CGO_ENABLED=0 go build -o xray -trimpath -buildvcs=false -ldflags="-X github.com/xtls/xray-core/core.build=REPLACE -s -w -buildid=" -v ./main
```

## Stargazers over time

[![Stargazers over time](https://starchart.cc/XTLS/Xray-core.svg)](https://starchart.cc/XTLS/Xray-core)

## HTTP API 接口文档

Xray-core提供了HTTP API接口，可以通过HTTP请求动态管理Xray配置。
xray run -c config.json
xray httpapi -api "127.0.0.1:10089" -http ":8080" -config "http-api.json"
### 基本配置

在Xray配置中添加以下内容启用HTTP API：

```json
{
  "api": {
    "tag": "api",
    "services": ["HandlerService", "StatsService", "LoggerService", "RoutersService"]
  },
  "inbounds": [
    {
      "tag": "api",
      "listen": "127.0.0.1",
      "port": 8080,
      "protocol": "dokodemo-door",
      "settings": {
        "address": "127.0.0.1"
      }
    }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "inboundTag": ["api"],
        "outboundTag": "api"
      }
    ]
  }
}
```

### API 接口说明

以下是主要的HTTP API接口：

#### 1. 测试API连接

- **URL**: `/api/test`
- **方法**: GET
- **描述**: 测试API服务器是否正常运行
- **响应**:
  ```json
  {
    "success": true,
    "message": "API服务器正常运行"
  }
  ```

#### 2. 路由规则管理

##### 2.1 添加路由规则

- **URL**: `/api/rules`
- **方法**: POST
- **描述**: 添加一条或多条路由规则
- **请求体**:
  ```json
  {
    "routing": {
      "domainStrategy": "IPIfNonMatch",
      "rules": [
        {
          "type": "field",
          "inboundTag": "socks1",
          "outboundTag": "proxy1",
          "ruleTag": "rule-test"
        }
      ]
    }
  }
  ```
- **响应**:
  ```json
  {
    "success": true,
    "message": "规则添加成功"
  }
  ```

##### 2.2 添加单个规则

- **URL**: `/api/add_rule`
- **方法**: POST
- **描述**: 添加单个路由规则
- **请求体**:
  ```json
  {
    "type": "field",
    "outboundTag": "proxy1",
    "inboundTag": "socks1",
    "ruleTag": "rule-test",
    "domain": ["example.com"],
    "ip": ["8.8.8.8"],
    "port": "53",
    "network": "tcp",
    "protocol": ["http"]
  }
  ```
- **响应**:
  ```json
  {
    "success": true,
    "message": "规则添加成功"
  }
  ```

##### 2.3 删除规则

- **URL**: `/api/rules/remove`
- **方法**: POST
- **描述**: 通过ruleTag删除规则
- **请求体**:
  ```json
  {
    "ruleTag": "rule-test"
  }
  ```
- **响应**:
  ```json
  {
    "success": true,
    "message": "规则 rule-test 删除成功"
  }
  ```

##### 2.4 列出所有规则

- **URL**: `/api/rules/list`
- **方法**: GET
- **描述**: 获取所有路由规则
- **响应**:
  ```json
  {
    "success": true,
    "data": [
      {
        "type": "field",
        "inboundTag": "socks1",
        "outboundTag": "proxy1",
        "ruleTag": "rule-test"
      }
    ]
  }
  ```

#### 3. 入站配置管理

##### 3.1 添加Socks入站

- **URL**: `/api/inbounds/socks`
- **方法**: POST
- **描述**: 添加一个Socks入站
- **请求体**:
  ```json
  {
    "tag": "socks1",
    "port": 20808,
    "listen": "127.0.0.1",
    "protocol": "socks",
    "settings": {
      "auth": "password",
      "accounts": [
        {
          "user": "user",
          "pass": "password"
        }
      ],
      "udp": true
    }
  }
  ```
- **响应**:
  ```json
  {
    "success": true,
    "message": "Socks入站添加成功"
  }
  ```

##### 3.2 删除入站

- **URL**: `/api/inbounds/remove`
- **方法**: POST
- **描述**: 通过tag删除入站
- **请求体**:
  ```json
  {
    "tag": "socks1"
  }
  ```
- **响应**:
  ```json
  {
    "success": true,
    "message": "入站 socks1 删除成功"
  }
  ```

##### 3.3 列出所有入站

- **URL**: `/api/inbounds/list`
- **方法**: GET
- **描述**: 获取所有入站配置
- **响应**:
  ```json
  {
    "success": true,
    "data": [
      {
        "tag": "socks1",
        "port": 20808,
        "listen": "127.0.0.1",
        "protocol": "socks"
      }
    ]
  }
  ```

#### 4. 出站配置管理

##### 4.1 添加出站

- **URL**: `/api/outbounds`
- **方法**: POST
- **描述**: 添加一个出站配置
- **请求体**:
  ```json
  {
    "tag": "proxy1",
    "protocol": "vmess",
    "settings": {
      "vnext": [
        {
          "address": "example.com",
          "port": 443,
          "users": [
            {
              "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
              "alterId": 0,
              "security": "auto"
            }
          ]
        }
      ]
    },
    "streamSettings": {
      "network": "ws",
      "security": "tls",
      "tlsSettings": {
        "serverName": "example.com"
      },
      "wsSettings": {
        "path": "/path"
      }
    }
  }
  ```
- **响应**:
  ```json
  {
    "success": true,
    "message": "出站添加成功"
  }
  ```

##### 4.2 从URI添加出站

- **URL**: `/api/outbounds/uri`
- **方法**: POST
- **描述**: 从分享链接(URI)添加出站
- **请求体**:
  ```json
  {
    "uri": "vmess://xxxxxxxxxxxxxxxx",
    "tag": "proxy1"
  }
  ```
- **响应**:
  ```json
  {
    "success": true,
    "message": "出站从URI添加成功"
  }
  ```

##### 4.3 删除出站

- **URL**: `/api/outbounds/remove`
- **方法**: POST
- **描述**: 通过tag删除出站
- **请求体**:
  ```json
  {
    "tag": "proxy1"
  }
  ```
- **响应**:
  ```json
  {
    "success": true,
    "message": "出站 proxy1 删除成功"
  }
  ```

##### 4.4 列出所有出站

- **URL**: `/api/outbounds/list`
- **方法**: GET
- **描述**: 获取所有出站配置
- **响应**:
  ```json
  {
    "success": true,
    "data": [
      {
        "tag": "proxy1",
        "protocol": "vmess",
        "address": "example.com",
        "port": 443
      }
    ]
  }
  ```

#### 5. 统计信息

- **URL**: `/api/stats`
- **方法**: GET
- **描述**: 获取流量统计信息
- **响应**:
  ```json
  {
    "success": true,
    "data": {
      "inbounds": {
        "socks1": {
          "downlink": 1024,
          "uplink": 2048
        }
      },
      "outbounds": {
        "proxy1": {
          "downlink": 1024,
          "uplink": 2048
        }
      }
    }
  }
  ```

#### 6. 重新加载配置

- **URL**: `/api/reload`
- **方法**: POST
- **描述**: 重新加载所有配置
- **响应**:
  ```json
  {
    "success": true,
    "message": "配置重新加载完成",
    "data": {
      "inbounds": ["socks1"],
      "outbounds": ["proxy1"],
      "rules": ["rule-test"]
    }
  }
  ```

### 注意事项

1. 所有API请求需要确保Xray-core正在运行，并且已正确配置API入站
2. 建议在本地使用，或者通过HTTPS加密传输，避免配置信息泄露
3. 添加规则时，优先使用`ruleTag`字段作为规则的唯一标识
4. 所有入站和出站都必须有唯一的`tag`字段作为标识

### 使用示例

使用curl发送请求：

```bash
# 添加规则
curl -X POST http://127.0.0.1:8080/api/rules -d '{
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      {
        "type": "field",
        "inboundTag": "socks1",
        "outboundTag": "proxy1",
        "ruleTag": "rule-test"
      }
    ]
  }
}'

# 删除规则
curl -X POST http://127.0.0.1:8080/api/rules/remove -d '{
  "ruleTag": "rule-test"
}'

# 重新加载配置
curl -X POST http://127.0.0.1:8080/api/reload
```
