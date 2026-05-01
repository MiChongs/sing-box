package main

import (
	"context"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	runtimeDebug "runtime/debug"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/sagernet/sing-box"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badjson"

	"github.com/spf13/cobra"
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
	// 防御：sing/common/json/internal/contextjson 的 comment 解析器在遇到
	// malformed JSON（典型：未闭合字符串如 `"server": "dns_hosts<EOL>`）时，
	// skipJSONString 一路扫到 EOF → parseObject/parseArray 解析器 desync →
	// p.nodes append 死循环，最终 3GB+ OOM 杀掉进程，没有清晰错误。
	// 先用一个 cheap 的状态机做语法粗校验：注释剥离 + 引号/括号配平，
	// 不合法直接报告精确位置；通过后再交给 sing 的完整解析器，避免触发 OOM。
	if err := preValidateJSONSyntax(configContent); err != nil {
		return nil, E.Cause(err, "config syntax check at ", path)
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
			if !strings.HasSuffix(entry.Name(), ".json") || entry.IsDir() {
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
	if len(optionsList) == 1 {
		return optionsList[0].options, nil
	}
	var mergedMessage json.RawMessage
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

func create() (*box.Box, context.CancelFunc, error) {
	options, err := readConfigAndMerge()
	if err != nil {
		return nil, nil, err
	}
	if disableColor {
		if options.Log == nil {
			options.Log = &option.LogOptions{}
		}
		options.Log.DisableColor = true
	}
	ctx, cancel := context.WithCancel(globalCtx)
	instance, err := box.New(box.Options{
		Context: ctx,
		Options: options,
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
	osSignals := make(chan os.Signal, 1)
	signal.Notify(osSignals, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(osSignals)
	for {
		instance, cancel, err := create()
		if err != nil {
			return err
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
