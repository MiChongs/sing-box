package main

import (
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	_ "github.com/sagernet/gomobile"
	"github.com/sagernet/sing-box/cmd/internal/build_shared"
	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/rw"
	"github.com/sagernet/sing/common/shell"
)

var (
	debugEnabled bool
	target       string
	platform     string
	// withTailscale bool
)

func init() {
	flag.BoolVar(&debugEnabled, "debug", false, "enable debug")
	flag.StringVar(&target, "target", "android", "target platform")
	flag.StringVar(&platform, "platform", "", "specify platform")
	// flag.BoolVar(&withTailscale, "with-tailscale", false, "build tailscale for iOS and tvOS")
}

func main() {
	flag.Parse()

	switch target {
	case "android":
		build_shared.FindMobile()
		buildAndroid()
	case "android-bin":
		buildAndroidBinary()
	case "apple":
		build_shared.FindMobile()
		buildApple()
	}
}

var (
	sharedFlags []string
	debugFlags  []string
	sharedTags  []string
	darwinTags  []string
	// memcTags    []string
	notMemcTags []string
	debugTags   []string
)

func init() {
	sharedFlags = append(sharedFlags, "-trimpath")
	sharedFlags = append(sharedFlags, "-buildvcs=false")
	currentTag, err := build_shared.ReadTag()
	if err != nil {
		currentTag = "unknown"
	}
	sharedFlags = append(sharedFlags, "-ldflags", "-X github.com/sagernet/sing-box/constant.Version="+currentTag+" -X internal/godebug.defaultGODEBUG=multipathtcp=0 -s -w -buildid=  -checklinkname=0")
	debugFlags = append(debugFlags, "-ldflags", "-X github.com/sagernet/sing-box/constant.Version="+currentTag+" -X internal/godebug.defaultGODEBUG=multipathtcp=0 -checklinkname=0")

	sharedTags = append(sharedTags, "with_gvisor", "with_quic", "with_wireguard", "with_utls", "with_naive_outbound", "with_clash_api", "badlinkname", "tfogo_checklinkname0")
	darwinTags = append(darwinTags, "with_dhcp", "grpcnotrace")
	// memcTags = append(memcTags, "with_tailscale")
	sharedTags = append(sharedTags, "with_tailscale", "ts_omit_logtail", "ts_omit_ssh", "ts_omit_drive", "ts_omit_taildrop", "ts_omit_webclient", "ts_omit_doctor", "ts_omit_capture", "ts_omit_kube", "ts_omit_aws", "ts_omit_synology", "ts_omit_bird")
	notMemcTags = append(notMemcTags, "with_low_memory")
	debugTags = append(debugTags, "debug")
}

type AndroidBuildConfig struct {
	AndroidAPI int
	OutputName string
	Tags       []string
}

func filterTags(tags []string, exclude ...string) []string {
	excludeMap := make(map[string]bool)
	for _, tag := range exclude {
		excludeMap[tag] = true
	}
	var result []string
	for _, tag := range tags {
		if !excludeMap[tag] {
			result = append(result, tag)
		}
	}
	return result
}

func checkJavaVersion() {
	var javaPath string
	javaHome := os.Getenv("JAVA_HOME")
	if javaHome == "" {
		javaPath = "java"
	} else {
		javaPath = filepath.Join(javaHome, "bin", "java")
	}

	javaVersion, err := shell.Exec(javaPath, "--version").ReadOutput()
	if err != nil {
		log.Fatal(E.Cause(err, "check java version"))
	}
	javaVersionLower := strings.ToLower(javaVersion)
	var majorVersion int
	for _, prefix := range []string{"openjdk ", "java "} {
		if idx := strings.Index(javaVersionLower, prefix); idx >= 0 {
			versionStr := javaVersionLower[idx+len(prefix):]
			for i, c := range versionStr {
				if c < '0' || c > '9' {
					versionStr = versionStr[:i]
					break
				}
			}
			majorVersion, _ = strconv.Atoi(versionStr)
			break
		}
	}
	if majorVersion < 17 {
		log.Fatal("java version should be 17 or higher, got: ", strings.TrimSpace(strings.Split(javaVersion, "\n")[0]))
	}
}

func getAndroidBindTarget() string {
	if platform != "" {
		return platform
	} else if debugEnabled {
		return "android/arm64"
	}
	return "android"
}

func buildAndroidVariant(config AndroidBuildConfig, bindTarget string) {
	args := []string{
		"bind",
		"-v",
		"-o", config.OutputName,
		"-target", bindTarget,
		"-androidapi", strconv.Itoa(config.AndroidAPI),
		"-javapkg=io.nekohasekai",
		"-libname=box",
	}

	if !debugEnabled {
		args = append(args, sharedFlags...)
	} else {
		args = append(args, debugFlags...)
	}

	args = append(args, "-tags", strings.Join(config.Tags, ","))
	args = append(args, "./experimental/libbox")

	command := exec.Command(build_shared.GoBinPath+"/gomobile", args...)
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	err := command.Run()
	if err != nil {
		log.Fatal(err)
	}

	copyPath := filepath.Join("..", "sing-box-for-android", "app", "libs")
	if rw.IsDir(copyPath) {
		copyPath, _ = filepath.Abs(copyPath)
		err = rw.CopyFile(config.OutputName, filepath.Join(copyPath, config.OutputName))
		if err != nil {
			log.Fatal(err)
		}
		log.Info("copied ", config.OutputName, " to ", copyPath)
	}
}

func buildAndroid() {
	build_shared.FindSDK()
	checkJavaVersion()

	bindTarget := getAndroidBindTarget()

	// Build main variant (SDK 23)
	mainTags := append([]string{}, sharedTags...)
	// mainTags = append(mainTags, memcTags...)
	if debugEnabled {
		mainTags = append(mainTags, debugTags...)
	}
	buildAndroidVariant(AndroidBuildConfig{
		AndroidAPI: 23,
		OutputName: "libbox.aar",
		Tags:       mainTags,
	}, bindTarget)

	// Build legacy variant (SDK 21, no naive outbound)
	legacyTags := filterTags(sharedTags, "with_naive_outbound")
	// legacyTags = append(legacyTags, memcTags...)
	if debugEnabled {
		legacyTags = append(legacyTags, debugTags...)
	}
	buildAndroidVariant(AndroidBuildConfig{
		AndroidAPI: 21,
		OutputName: "libbox-legacy.aar",
		Tags:       legacyTags,
	}, bindTarget)
}

func buildApple() {
	var bindTarget string
	if platform != "" {
		bindTarget = platform
	} else if debugEnabled {
		bindTarget = "ios"
	} else {
		bindTarget = "ios,iossimulator,tvos,tvossimulator,macos"
	}

	args := []string{
		"bind",
		"-v",
		"-target", bindTarget,
		"-libname=box",
		"-tags-not-macos=with_low_memory",
		"-iosversion=15.0",
		"-macosversion=13.0",
		"-tvosversion=17.0",
	}
	//if !withTailscale {
	//	args = append(args, "-tags-macos="+strings.Join(memcTags, ","))
	//}

	if !debugEnabled {
		args = append(args, sharedFlags...)
	} else {
		args = append(args, debugFlags...)
	}

	tags := append(sharedTags, darwinTags...)
	//if withTailscale {
	//	tags = append(tags, memcTags...)
	//}
	if debugEnabled {
		tags = append(tags, debugTags...)
	}

	args = append(args, "-tags", strings.Join(tags, ","))
	args = append(args, "./experimental/libbox")

	command := exec.Command(build_shared.GoBinPath+"/gomobile", args...)
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	err := command.Run()
	if err != nil {
		log.Fatal(err)
	}

	copyPath := filepath.Join("..", "sing-box-for-apple")
	if rw.IsDir(copyPath) {
		targetDir := filepath.Join(copyPath, "Libbox.xcframework")
		targetDir, _ = filepath.Abs(targetDir)
		os.RemoveAll(targetDir)
		os.Rename("Libbox.xcframework", targetDir)
		log.Info("copied to ", targetDir)
	}
}

type androidArch struct {
	goArch string
	clang  string
	abi    string
}

var androidArchList = []androidArch{
	{"arm64", "aarch64-linux-android", "arm64-v8a"},
	{"arm", "armv7a-linux-androideabi", "armeabi-v7a"},
	{"amd64", "x86_64-linux-android", "x86_64"},
	{"386", "i686-linux-android", "x86"},
}

func buildAndroidBinary() {
	build_shared.FindSDK()

	ndkPath := os.Getenv("ANDROID_NDK_HOME")
	hostOS := "linux"
	switch runtime.GOOS {
	case "windows":
		hostOS = "windows"
	case "darwin":
		hostOS = "darwin"
	}
	ndkBin := filepath.Join(ndkPath, "toolchains", "llvm", "prebuilt", hostOS+"-x86_64", "bin")

	// Create empty stub archives for libraries that exist on standard Linux
	// but are built into Android's bionic libc (pthread, rt, resolv).
	// Go's linker and CGO dependencies (e.g. cronet-go) unconditionally
	// link against these. This is the standard workaround for Android CGO.
	stubDir, err := os.MkdirTemp("", "android-bionic-stubs")
	if err != nil {
		log.Fatal(E.Cause(err, "create stub directory"))
	}
	defer os.RemoveAll(stubDir)

	arTool := filepath.Join(ndkBin, "llvm-ar")
	if runtime.GOOS == "windows" {
		arTool += ".exe"
	}
	for _, libName := range []string{"libpthread.a", "librt.a", "libresolv.a"} {
		stubLib := filepath.Join(stubDir, libName)
		arCmd := exec.Command(arTool, "cr", stubLib)
		arCmd.Stderr = os.Stderr
		if err = arCmd.Run(); err != nil {
			log.Fatal(E.Cause(err, "create "+libName+" stub"))
		}
	}

	androidAPI := "24"
	// Use full build tags from release/DEFAULT_BUILD_TAGS_OTHERS + netgo for Android CGO DNS compat
	defaultTagsBytes, readErr := os.ReadFile("release/DEFAULT_BUILD_TAGS_OTHERS")
	var tags []string
	if readErr == nil {
		tags = strings.Split(strings.TrimSpace(string(defaultTagsBytes)), ",")
	} else {
		tags = append([]string{}, sharedTags...)
	}
	tags = append(tags, "with_naive_outbound", "netgo")
	// deduplicate
	seen := make(map[string]bool)
	deduped := tags[:0]
	for _, t := range tags {
		if t != "" && !seen[t] {
			seen[t] = true
			deduped = append(deduped, t)
		}
	}
	tags = deduped
	if debugEnabled {
		tags = append(tags, debugTags...)
	}

	var archList []androidArch
	if platform != "" {
		// e.g. platform = "android/arm64"
		parts := strings.Split(platform, "/")
		goarch := parts[len(parts)-1]
		for _, arch := range androidArchList {
			if arch.goArch == goarch {
				archList = append(archList, arch)
				break
			}
		}
		if len(archList) == 0 {
			log.Fatal("unsupported platform: ", platform)
		}
	} else {
		archList = androidArchList
	}

	for _, arch := range archList {
		outputName := "sing-box-android-" + arch.abi
		log.Info("building ", outputName, " (GOARCH=", arch.goArch, ")")

		cc := filepath.Join(ndkBin, arch.clang+androidAPI+"-clang")
		cxx := filepath.Join(ndkBin, arch.clang+androidAPI+"-clang++")
		if runtime.GOOS == "windows" {
			cc += ".cmd"
			cxx += ".cmd"
		}

		args := []string{
			"build",
			"-buildmode=pie",
			"-v",
			"-trimpath",
			"-buildvcs=false",
		}
		// Use debugFlags (no -s -w strip) for full binary; sharedFlags strips symbols
		args = append(args, debugFlags...)
		args = append(args, "-tags", strings.Join(tags, ","))
		args = append(args, "-o", outputName)
		args = append(args, "./cmd/sing-box")

		command := exec.Command("go", args...)
		command.Env = append(os.Environ(),
			"CGO_ENABLED=1",
			"GOOS=android",
			"GOARCH="+arch.goArch,
			"CC="+cc,
			"CXX="+cxx,
			"CGO_LDFLAGS=-L"+stubDir,
		)
		if arch.goArch == "arm" {
			command.Env = append(command.Env, "GOARM=7")
		}
		command.Stdout = os.Stdout
		command.Stderr = os.Stderr
		if err = command.Run(); err != nil {
			log.Fatal(E.Cause(err, "build "+outputName))
		}
		log.Info("built ", outputName)
	}
}
