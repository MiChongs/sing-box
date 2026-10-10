### 结构

```json
{
  "type": "urltest",
  "tag": "auto",
  
  "outbounds": [
    "proxy-a",
    "proxy-b",
    "proxy-c"
  ],
  "providers": [
    "provider-a",
    "provider-b",
  ],
  "exclude": "",
  "include": "",
  "url": "",
  "interval": "",
  "tolerance": 50,
  "idle_timeout": "",
  "use_all_providers": false,
  "fallback": {
    "enabled": false,
    "max_delay": ""
  },
  "interrupt_exist_connections": false
}
```

### 字段

#### outbounds

用于测试的出站标签列表。

#### providers

用于测试的[订阅](/zh/configuration/provider)标签列表。

#### exclude

排除 `providers` 节点的正则表达式。

#### include

包含 `providers` 节点的正则表达式。

#### url

用于测试的链接。默认使用 `https://www.gstatic.com/generate_204`。

#### interval

测试间隔。 默认使用 `3m`。

每个间隔都会测试当前选择、延迟最低的 3 个成员以及从未测试过的成员。
其余成员每 4 个间隔刷新一次。
连续测试失败的成员按 1、2、4 直至 8 个间隔退避重试；网络变化时重置退避。

其他组或 API 刚测过的成员不会重复测试，多个组同时测试同一成员时只发起一次测试。
所有组的测试在同一时刻进行，间隔相同的组每个间隔只唤醒一次网络。
网络变化后会重新测试当前选择和延迟最低的成员，最多每 30 秒一次。

#### tolerance

以毫秒为单位的测试容差。 默认使用 `50`。

#### idle_timeout

空闲超时。默认使用 `30m`。

#### use_all_providers

是否使用所有提供者。默认使用 `false`。

#### fallback

回退选择配置。

启用后，将按配置顺序选择首个可用出站，而不是选择延迟最低的出站。

##### fallback.enabled

启用回退选择。

##### fallback.max_delay

可接受的最大延迟。

延迟超过该值的出站会被跳过。如果所有可用出站均超过该值，则选择其中延迟最低的出站。

#### interrupt_exist_connections

当选定的出站发生更改时，中断现有连接。

仅入站连接受此设置影响，内部连接将始终被中断。
