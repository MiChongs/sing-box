//go:build !with_xhttp

package include

// XHTTP 未编入：不做任何注册，option.V2RayTransportOptions 遇到
// "type": "xhttp" 的配置会在 UnmarshalJSON 报
// "unknown transport type: xhttp"，用户得知需要带 -tags with_xhttp 重编。
