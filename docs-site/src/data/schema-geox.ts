// experimental.geox — mirrors option/experimental.go:42 (GeoXOptions).
import type { FieldDef } from './schema-smart-outbound';

export const geoxTop: FieldDef[] = [
  {
    name: 'enabled',
    type: 'bool',
    default: 'false',
    descZh: '总开关（mihomo 称 `geodata-mode`）。关闭时所有 geo 下载跳过；Smart 组如需 ASN 请提供 `asn_database`。',
    descEn: 'Master switch (mihomo calls it `geodata-mode`). When off, all geo downloads skip; provide `asn_database` directly if Smart needs ASN.',
  },
  {
    name: 'auto_update',
    type: 'bool',
    default: 'false',
    descZh: '周期性刷新 geoip / geosite / mmdb / ASN 四组文件。',
    descEn: 'Periodically refresh all four file groups (geoip / geosite / mmdb / ASN).',
  },
  {
    name: 'update_interval',
    type: 'duration',
    default: '24h',
    descZh: '自动更新周期。默认每天；MaxMind 免费版通常每周更新一次，太短没必要。',
    descEn: 'Update cadence. Default daily; MaxMind free tier updates weekly anyway.',
  },
  {
    name: 'download_detour',
    type: 'string',
    descZh: '下载所有 geo 文件走哪个出站。同 `smart.lightgbm.download_detour`，通常直连。',
    descEn: 'Outbound tag for all geo file downloads. Same convention as `smart.lightgbm.download_detour`; usually direct.',
  },
];

export const geoxUrl: FieldDef[] = [
  {
    name: 'url.geoip',
    type: 'string',
    descZh: '可选 geoip.dat 下载链接。当前仅为 Smart 以外场景预留，Smart 只消费 ASN。',
    descEn: 'Optional geoip.dat URL. Currently reserved for non-Smart consumers — Smart only uses ASN.',
  },
  {
    name: 'url.geosite',
    type: 'string',
    descZh: '可选 geosite.dat 下载链接。',
    descEn: 'Optional geosite.dat URL.',
  },
  {
    name: 'url.mmdb',
    type: 'string',
    descZh: 'Country mmdb 下载链接（如 MaxMind GeoLite2-Country.mmdb）。',
    descEn: 'Country mmdb URL (e.g. MaxMind GeoLite2-Country.mmdb).',
  },
  {
    name: 'url.asn',
    type: 'string | string[]',
    descZh: 'ASN mmdb 下载链接；支持多源 fallback（Listable）。如 `["maxmind-asn.mmdb", "ipinfo-asn.mmdb"]`。Smart 组在查询 ASN 时按顺序尝试，首个命中即返回。',
    descEn: 'ASN mmdb URL(s); supports multi-source fallback (Listable). Smart queries in order and returns first hit.',
    notes: 'Listable[string]',
  },
];

export default { geoxTop, geoxUrl };
