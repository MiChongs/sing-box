### 结构

```json
{
  "type": "nested",
  "tag": "chain",

  "detour": "entry",
  "outbounds": [
    "exit-a",
    "exit-b"
  ],
  "providers": [],
  "default": "exit-a",

  ... // 选择器字段
}
```

nested 组实现两跳链式代理：每个连接先经过 `detour`（入口），再到所选的出口。它是一个成员经 `detour` 拨号的 [选择器](/zh/configuration/outbound/selector/)。

组会为每个出口（静态出站与 provider 节点）按其原配置创建一个影子出站，命名为 `<出口标签>@<组标签>`，并把 `detour` 设为入口，注册到出站管理器。出口配置不变时复用影子出站，provider 更新配置时重建。原出站仍然直接拨号。`direct` 与 `block` 成员按原样使用。

组本身或 `detour` 退化为 `Compatible`（没有可用成员）时，组会阻断所有连接，避免直连出口泄露真实 IP，或让入口看到未封装的出口流量。

与选择器一样通过 [Clash API](/zh/configuration/experimental/clash-api/) 切换；`exit-a` 与 `exit-a@chain` 选择的是同一个成员。

### 字段

#### detour

==必填==

入口出站的标签，不能是组自身。

#### outbounds / providers / default / ...

参阅 [选择器](/zh/configuration/outbound/selector/)。`outbounds` 与 `providers` 至少填一个。
