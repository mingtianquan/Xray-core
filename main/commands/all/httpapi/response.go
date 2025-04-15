package httpapi

import (
	"encoding/json"
	"net/http"
)

// 响应结构
type Response struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

// 发送JSON响应
func SendJSONResponse(w http.ResponseWriter, success bool, message string, data interface{}) {
	response := Response{
		Success: success,
		Message: message,
		Data:    data,
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if !success {
		w.WriteHeader(http.StatusBadRequest)
	}

	encoder := json.NewEncoder(w)
	// 不转义HTML字符
	encoder.SetEscapeHTML(false)
	// 对中文使用原样输出，不使用Unicode编码
	encoder.SetIndent("", "  ")
	encoder.Encode(response)
}
