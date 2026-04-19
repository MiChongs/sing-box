// experimental.smart — mirrors option/experimental.go:19 (SmartOptions).
// Two nested blocks: lightgbm (model) + collector (CSV training data).
import type { FieldDef } from './schema-smart-outbound';

export const smartLightgbm: FieldDef[] = [
  {
    name: 'url',
    type: 'string',
    default: 'mihomo Model-large.bin',
    descZh: 'LightGBM 模型 .bin 下载地址。空时用内置 mihomo 预训练模型 URL。',
    descEn: 'LightGBM .bin model download URL. Empty uses the built-in mihomo Model-large.bin URL.',
  },
  {
    name: 'auto_update',
    type: 'bool',
    default: 'false',
    descZh: '周期性刷新模型文件。启用后按 `update_interval` 拉取。',
    descEn: 'Periodically refresh the model file on `update_interval`.',
  },
  {
    name: 'update_interval',
    type: 'duration',
    default: '72h',
    descZh: '自动更新周期。默认 3 天；模型通常迭代缓慢，无需激进刷新。',
    descEn: 'Auto-update cadence. Default 3 days; models iterate slowly so aggressive refresh adds no value.',
  },
  {
    name: 'model_path',
    type: 'string',
    default: 'smart_lgbm_model.bin',
    descZh: '本地落盘路径，相对于 sing-box 数据目录。',
    descEn: 'Local on-disk path, relative to sing-box base path.',
  },
  {
    name: 'download_detour',
    type: 'string',
    descZh: '下载模型文件走哪个出站 tag。通常指向直连或已验证过的节点，避免用未测试的 Smart 组下载自己的模型。',
    descEn: 'Outbound tag used to fetch the model file. Typically direct or a known-good proxy — avoid self-referencing.',
  },
];

export const smartCollector: FieldDef[] = [
  {
    name: 'size_limit_mb',
    type: 'int64',
    default: '100',
    descZh: 'CSV 文件大小上限（MB）。超过后新样本静默丢弃，直到用户手动删除或扩大上限。',
    descEn: 'CSV size cap (MB). Past this, new samples are silently dropped until you delete the file or raise the cap.',
  },
  {
    name: 'path',
    type: 'string',
    default: 'smart_weight_data.csv',
    descZh: 'CSV 输出路径，相对于 sing-box 数据目录。',
    descEn: 'CSV output path, relative to sing-box base path.',
  },
];

export default { smartLightgbm, smartCollector };
