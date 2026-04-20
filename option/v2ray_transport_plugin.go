package option

import "sync"

// V2RayTransportOptionFactory 分配一个零值的插件 options 实例（通常是
// *V2RayXHTTPOptions 之类的指针类型），由 V2RayTransportOptions.UnmarshalJSON
// 在遇到未知 type 时调用，拿到实例后 badjson.UnmarshallExcluded 填字段。
// 返回的值会存进 V2RayTransportOptions.Extra。
type V2RayTransportOptionFactory func() any

var (
	v2rayTransportOptionFactoryAccess sync.RWMutex
	v2rayTransportOptionFactoryMap    = map[string]V2RayTransportOptionFactory{}
)

// RegisterV2RayTransportOptions 注册一个 transport 类型名（如 "xhttp"）
// 到它的 options 工厂。插件包在 init() 里调用。
func RegisterV2RayTransportOptions(name string, factory V2RayTransportOptionFactory) {
	v2rayTransportOptionFactoryAccess.Lock()
	defer v2rayTransportOptionFactoryAccess.Unlock()
	v2rayTransportOptionFactoryMap[name] = factory
}

func lookupV2RayTransportOptionFactory(name string) (V2RayTransportOptionFactory, bool) {
	v2rayTransportOptionFactoryAccess.RLock()
	defer v2rayTransportOptionFactoryAccess.RUnlock()
	factory, ok := v2rayTransportOptionFactoryMap[name]
	return factory, ok
}
