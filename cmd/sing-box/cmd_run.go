package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	runtimeDebug "runtime/debug"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badjson"
	"github.com/sagernet/sing/service"

	"github.com/spf13/cobra"
	"sigs.k8s.io/yaml"
)

var commandRun = &cobra.Command{
	Use:   "run",
	Short: "Run service",
	Run: func(cmd *cobra.Command, args []string) {
		err := run()
		if err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	mainCommand.AddCommand(commandRun)
}

type OptionsEntry struct {
	content []byte
	path    string
	options option.Options
}

func readConfigAt(path string) (*OptionsEntry, error) {
	var (
		configContent []byte
		err           error
	)
	if path == "stdin" {
		configContent, err = io.ReadAll(os.Stdin)
	} else {
		configContent, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, E.Cause(err, "read config at ", path)
	}
	configContent, err = normalizeConfigContent(path, configContent)
	if err != nil {
		return nil, err
	}

	configContent, err = applyConfigFilter(configContent)
	if err != nil {
		return nil, E.Cause(err, "filter config at ", path)
	}
	options, err := json.UnmarshalExtendedContext[option.Options](globalCtx, configContent)
	if err != nil {
		return nil, E.Cause(err, "decode config at ", path)
	}
	return &OptionsEntry{
		content: configContent,
		path:    path,
		options: options,
	}, nil
}

// preValidateJSONSyntax 做一遍轻量状态机预校验：剥离 // 行注释 / # 行注释 /
// /* */ 块注释，保持引号/转义/括号语义，最终检查 string/object/array 是否配平。
// 不合法直接返回带行列号的错误。目的是在 sing 库的 comment parser 因 malformed
// 输入死循环 OOM 之前，给出可读的语法错误。
func preValidateJSONSyntax(data []byte) error {
	var (
		braceDepth   int
		bracketDepth int
		stringStart  = -1
		stringStartL = 0
		stringStartC = 0
		line         = 1
		col          = 1
	)
	advance := func(c byte) {
		if c == '\n' {
			line++
			col = 1
		} else {
			col++
		}
	}
	for i := 0; i < len(data); i++ {
		c := data[i]
		// 字符串内：仅识别 \\<x> 转义和 " 闭合。出现裸 \n / \r 即未闭合。
		if stringStart >= 0 {
			switch c {
			case '\\':
				if i+1 < len(data) {
					advance(c)
					advance(data[i+1])
					i++
				} else {
					return E.New("unterminated string literal at line ", stringStartL, " column ", stringStartC)
				}
				continue
			case '"':
				stringStart = -1
				advance(c)
				continue
			case '\n', '\r':
				return E.New("unterminated string literal at line ", stringStartL, " column ", stringStartC, " (raw control character inside string)")
			}
			advance(c)
			continue
		}
		// 字符串外：处理注释 + 括号 + 引号。
		switch c {
		case '"':
			stringStart = i
			stringStartL = line
			stringStartC = col
			advance(c)
		case '{':
			braceDepth++
			advance(c)
		case '}':
			braceDepth--
			if braceDepth < 0 {
				return E.New("unmatched '}' at line ", line, " column ", col)
			}
			advance(c)
		case '[':
			bracketDepth++
			advance(c)
		case ']':
			bracketDepth--
			if bracketDepth < 0 {
				return E.New("unmatched ']' at line ", line, " column ", col)
			}
			advance(c)
		case '/':
			if i+1 < len(data) && data[i+1] == '/' {
				for i < len(data) && data[i] != '\n' {
					advance(data[i])
					i++
				}
				if i < len(data) {
					advance(data[i])
				}
			} else if i+1 < len(data) && data[i+1] == '*' {
				cmtL, cmtC := line, col
				advance(c)
				advance(data[i+1])
				i += 2
				for i+1 < len(data) && !(data[i] == '*' && data[i+1] == '/') {
					advance(data[i])
					i++
				}
				if i+1 >= len(data) {
					return E.New("unterminated block comment at line ", cmtL, " column ", cmtC)
				}
				advance(data[i])
				advance(data[i+1])
				i++
			} else {
				advance(c)
			}
		case '#':
			for i < len(data) && data[i] != '\n' {
				advance(data[i])
				i++
			}
			if i < len(data) {
				advance(data[i])
			}
		default:
			advance(c)
		}
	}
	if stringStart >= 0 {
		return E.New("unterminated string literal at line ", stringStartL, " column ", stringStartC)
	}
	if braceDepth != 0 {
		return E.New("brace mismatch: ", braceDepth, " unclosed '{' (expected closing '}')")
	}
	if bracketDepth != 0 {
		return E.New("bracket mismatch: ", bracketDepth, " unclosed '[' (expected closing ']')")
	}
	return nil
}

func readConfig() ([]*OptionsEntry, error) {
	var optionsList []*OptionsEntry
	for _, path := range configPaths {
		optionsEntry, err := readConfigAt(path)
		if err != nil {
			return nil, err
		}
		optionsList = append(optionsList, optionsEntry)
	}
	for _, directory := range configDirectories {
		entries, err := os.ReadDir(directory)
		if err != nil {
			return nil, E.Cause(err, "read config directory at ", directory)
		}
		for _, entry := range entries {
			ext := filepath.Ext(entry.Name())
			if (ext != ".json" && ext != ".jsonc" && ext != ".yaml" && ext != ".yml") || entry.IsDir() {
				continue
			}
			optionsEntry, err := readConfigAt(filepath.Join(directory, entry.Name()))
			if err != nil {
				return nil, err
			}
			optionsList = append(optionsList, optionsEntry)
		}
	}
	sort.Slice(optionsList, func(i, j int) bool {
		return optionsList[i].path < optionsList[j].path
	})
	return optionsList, nil
}

func readConfigAndMerge() (option.Options, error) {
	optionsList, err := readConfig()
	if err != nil {
		return option.Options{}, err
	}
	return mergeOptionsList(optionsList)
}

func mergeOptionsList(optionsList []*OptionsEntry) (option.Options, error) {
	if len(optionsList) == 1 {
		return optionsList[0].options, nil
	}
	var (
		mergedMessage json.RawMessage
		err           error
	)
	for _, options := range optionsList {
		mergedMessage, err = badjson.MergeJSON(globalCtx, options.options.RawMessage, mergedMessage, false)
		if err != nil {
			return option.Options{}, E.Cause(err, "merge config at ", options.path)
		}
	}
	var mergedOptions option.Options
	err = mergedOptions.UnmarshalJSONContext(globalCtx, mergedMessage)
	if err != nil {
		return option.Options{}, E.Cause(err, "unmarshal merged config")
	}
	return mergedOptions, nil
}

// configCheckerFunc exposes check to the Clash API, which reloads through the
// same path as SIGHUP.
type configCheckerFunc func() error

func (f configCheckerFunc) CheckConfig() error {
	return f()
}

func create(options option.Options) (*box.Box, context.CancelFunc, error) {
	if disableColor {
		if options.Log == nil {
			options.Log = &option.LogOptions{}
		}
		options.Log.DisableColor = true
	}
	ctx, cancel := context.WithCancel(service.ExtendContext(globalCtx))
	service.MustRegister[adapter.ConfigChecker](ctx, configCheckerFunc(check))
	instance, err := box.New(box.Options{
		Context:                    ctx,
		Options:                    options,
		NetworkNamespaceHolderArgs: []string{"/proc/self/exe", commandNetnsHolder.Use},
	})
	if err != nil {
		cancel()
		return nil, nil, E.Cause(err, "create service")
	}

	osSignals := make(chan os.Signal, 1)
	signal.Notify(osSignals, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer func() {
		signal.Stop(osSignals)
		close(osSignals)
	}()
	startCtx, finishStart := context.WithCancel(context.Background())
	go func() {
		_, loaded := <-osSignals
		if loaded {
			cancel()
			closeMonitor(startCtx)
		}
	}()
	err = instance.Start()
	finishStart()
	if err != nil {
		cancel()
		return nil, nil, E.Cause(err, "start service")
	}
	return instance, cancel, nil
}

func run() error {
	optionsList, err := readConfig()
	if err != nil {
		return err
	}
	options, err := mergeOptionsList(optionsList)
	if err != nil {
		return err
	}
	err = runInUserNamespaceIfNeeded(options, optionsList)
	if err != nil {
		return err
	}
	osSignals := make(chan os.Signal, 1)
	signal.Notify(osSignals, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(osSignals)
	for {
		instance, cancel, createErr := create(options)
		if createErr != nil {
			return createErr
		}
		runtimeDebug.FreeOSMemory()
		for {
			reloadTag := false
			select {
			case osSignal := <-osSignals:
				if osSignal == syscall.SIGHUP {
					err = check()
					if err != nil {
						log.Error(E.Cause(err, "reload service"))
						continue
					}
					reloadTag = true
				}
			case <-instance.ReloadChan():
				err = check()
				if err != nil {
					log.Error(E.Cause(err, "reload service"))
					continue
				}
				reloadTag = true
			}
			cancel()
			closeCtx, closed := context.WithCancel(context.Background())
			go closeMonitor(closeCtx)
			err = instance.Close()
			closed()
			if !reloadTag {
				if err != nil {
					log.Error(E.Cause(err, "sing-box did not closed properly"))
				}
				return nil
			}
			break
		}
		options, err = readConfigAndMerge()
		if err != nil {
			return err
		}
	}
}

func closeMonitor(ctx context.Context) {
	time.Sleep(C.FatalStopTimeout)
	select {
	case <-ctx.Done():
		return
	default:
	}
	log.Fatal("sing-box did not close!")
}

// normalizeConfigContent 统一把配置转换为 JSON：.yaml / .yml 或不以 { 开头的内容按 YAML 解析；
// 其余按 JSON（允许注释）处理，语法不合法时再尝试 YAML，两者都失败时报告 JSON 的精确错误位置。
func normalizeConfigContent(path string, content []byte) ([]byte, error) {
	ext := strings.ToLower(filepath.Ext(path))
	if ext != ".yaml" && ext != ".yml" && startsAsJSONObject(content) {
		// 防御：sing/common/json/internal/contextjson 的 comment 解析器在遇到
		// malformed JSON（典型：未闭合字符串如 `"server": "dns_hosts<EOL>`）时，
		// skipJSONString 一路扫到 EOF → parseObject/parseArray 解析器 desync →
		// p.nodes append 死循环，最终 3GB+ OOM 杀掉进程，没有清晰错误。
		// 先用一个 cheap 的状态机做语法粗校验：注释剥离 + 引号/括号配平，
		// 不合法直接报告精确位置；通过后再交给 sing 的完整解析器，避免触发 OOM。
		jsonErr := preValidateJSONSyntax(content)
		if jsonErr == nil {
			return content, nil
		}
		jsonContent, yamlErr := yamlToConfigJSON(content)
		if yamlErr != nil {
			return nil, E.Cause(jsonErr, "config syntax check at ", path)
		}
		return jsonContent, nil
	}
	jsonContent, err := yamlToConfigJSON(content)
	if err != nil {
		return nil, E.Cause(err, "parse YAML config at ", path)
	}
	return jsonContent, nil
}

// startsAsJSONObject 跳过 BOM、空白与 // 、/* */ 注释后判断内容是否以 { 开头。
func startsAsJSONObject(content []byte) bool {
	content = bytes.TrimPrefix(content, []byte("\xef\xbb\xbf"))
	for {
		content = bytes.TrimLeft(content, " \t\r\n")
		switch {
		case bytes.HasPrefix(content, []byte("//")):
			index := bytes.IndexByte(content, '\n')
			if index < 0 {
				return false
			}
			content = content[index+1:]
		case bytes.HasPrefix(content, []byte("/*")):
			index := bytes.Index(content[2:], []byte("*/"))
			if index < 0 {
				return false
			}
			content = content[index+4:]
		default:
			return len(content) > 0 && content[0] == '{'
		}
	}
}

// yamlToConfigJSON 把 YAML 转为 JSON，并丢弃顶层以 "."、"_"、"x-" 开头的键
// （常用来存放 YAML 锚点等辅助内容）。
func yamlToConfigJSON(content []byte) ([]byte, error) {
	jsonContent, err := yaml.YAMLToJSON(content)
	if err != nil {
		return nil, err
	}
	var root map[string]json.RawMessage
	if json.Unmarshal(jsonContent, &root) != nil {
		return jsonContent, nil
	}
	var cleaned bool
	for key := range root {
		if strings.HasPrefix(key, ".") || strings.HasPrefix(key, "_") || strings.HasPrefix(key, "x-") || strings.HasPrefix(key, "X-") {
			delete(root, key)
			cleaned = true
		}
	}
	if !cleaned {
		return jsonContent, nil
	}
	return json.Marshal(root)
}

// applyConfigFilter 在解析前按 filter_regex / filter_reverse 处理带 filter_mark 的条目，
// 并按命中的 filter_option 展开参数；配置中没有任何过滤字段时原样返回。
func applyConfigFilter(content []byte) ([]byte, error) {
	if !bytes.Contains(content, []byte("filter_")) {
		return content, nil
	}
	decoder := json.NewDecoder(json.NewCommentFilter(bytes.NewReader(content)))
	decoder.UseNumber()

	var root any
	if err := decoder.Decode(&root); err != nil {
		return content, nil
	}

	rootMap, ok := root.(map[string]any)
	if !ok {
		return content, nil
	}

	var changed bool
	filterRegex := regexp.MustCompile(`a\A`)
	if rawRegex, exists := rootMap["filter_regex"]; exists {
		changed = true
		delete(rootMap, "filter_regex")
		if regexStr, isStr := rawRegex.(string); isStr && regexStr != "" {
			compiled, err := regexp.Compile(regexStr)
			if err != nil {
				return nil, E.Cause(err, "invalid filter_regex pattern: ", regexStr)
			}
			filterRegex = compiled
		}
	}

	filterReverse := false
	if rawReverse, exists := rootMap["filter_reverse"]; exists {
		changed = true
		delete(rootMap, "filter_reverse")
		if revBool, isBool := rawReverse.(bool); isBool {
			filterReverse = revBool
		}
	}

	var prune func(v any) (any, bool)
	prune = func(v any) (any, bool) {
		switch node := v.(type) {
		case map[string]any:
			if rawMark, hasMark := node["filter_mark"]; hasMark {
				changed = true
				delete(node, "filter_mark")

				matched := false
				if markStr, isStr := rawMark.(string); isStr {
					matched = filterRegex.MatchString(markStr)
				} else if markArr, isArr := rawMark.([]any); isArr && len(markArr) > 0 {
					matched = true
					for _, item := range markArr {
						if markStr, isStr := item.(string); isStr {
							if !filterRegex.MatchString(markStr) {
								matched = false
								break
							}
						} else {
							matched = false
							break
						}
					}
				}

				shouldDestroy := (matched == filterReverse)
				if shouldDestroy {
					return nil, true
				}
			}

			if rawOption, hasOption := node["filter_option"]; hasOption {
				changed = true
				delete(node, "filter_option")

				if !filterReverse {
					if optMap, isMap := rawOption.(map[string]any); isMap {
						keys := make([]string, 0, len(optMap))
						for k := range optMap {
							keys = append(keys, k)
						}
						sort.Strings(keys)

						for _, mark := range keys {
							if filterRegex.MatchString(mark) {
								if subMap, ok := optMap[mark].(map[string]any); ok {
									for subKey, subVal := range subMap {
										if subVal == nil {
											delete(node, subKey)
										} else {
											node[subKey] = subVal
										}
									}
								}
							}
						}
					}
				}
			}

			for key, val := range node {
				newChild, shouldDelete := prune(val)
				if shouldDelete {
					delete(node, key)
				} else {
					node[key] = newChild
				}
			}
			return node, false

		case []any:
			newSlice := make([]any, 0, len(node))
			for _, item := range node {
				newItem, shouldDelete := prune(item)
				if !shouldDelete {
					newSlice = append(newSlice, newItem)
				}
			}
			return newSlice, false

		default:
			return node, false
		}
	}

	prune(rootMap)
	if !changed {
		return content, nil
	}
	return json.Marshal(rootMap)
}
