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
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/rw"
	"github.com/sagernet/sing/common/shell"
)

var (
	debugEnabled    bool
	target          string
	platform        string
	extraTags       string
	versionOverride string
	// withTailscale bool
)

func init() {
	flag.BoolVar(&debugEnabled, "debug", false, "enable debug")
	flag.StringVar(&target, "target", "android", "target platform")
	flag.StringVar(&platform, "platform", "", "specify platform")
	flag.StringVar(&extraTags, "tags", "", "additional comma separated build tags for android-bin")
	flag.StringVar(&versionOverride, "version", "", "version of the android-bin binary instead of git describe")
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
	sharedFlags = append(sharedFlags, "-ldflags", build_shared.LinkerFlags(currentTag, false))
	debugFlags = append(debugFlags, "-ldflags", build_shared.LinkerFlags(currentTag, true))

	sharedTags = append(sharedTags, "with_gvisor", "with_quic", "with_wireguard", "with_utls", "with_naive_outbound", "with_clash_api", "with_usbip", "with_openvpn", "with_openconnect", "badlinkname", "tfogo_checklinkname0")
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
	if !strings.Contains(javaVersion, "openjdk 17") {
		log.Fatal("java version should be openjdk 17")
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

	// Build main variant (SDK 24)
	mainTags := append([]string{}, sharedTags...)
	// mainTags = append(mainTags, memcTags...)
	if debugEnabled {
		mainTags = append(mainTags, debugTags...)
	}
	buildAndroidVariant(AndroidBuildConfig{
		AndroidAPI: 24,
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

// buildAndroidBinary builds the sing-box command line binary for Android with
// the NDK toolchain, including the naive outbound (cronet, CGO).
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

	// Empty stub archives for libraries that exist on standard Linux but are
	// built into Android's bionic libc (pthread, rt, resolv). Go's linker and
	// CGO dependencies (e.g. cronet-go) unconditionally link against these.
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
		arCommand := exec.Command(arTool, "cr", filepath.Join(stubDir, libName))
		arCommand.Stderr = os.Stderr
		if err = arCommand.Run(); err != nil {
			log.Fatal(E.Cause(err, "create ", libName, " stub"))
		}
	}

	const androidAPI = "24"
	// Full release tags plus netgo for the Android CGO DNS resolver.
	var tags []string
	defaultTags, err := os.ReadFile("release/DEFAULT_BUILD_TAGS_OTHERS")
	if err == nil {
		tags = strings.Split(strings.TrimSpace(string(defaultTags)), ",")
	} else {
		tags = append(tags, sharedTags...)
	}
	tags = append(tags, "with_naive_outbound", "netgo")
	if extraTags != "" {
		tags = append(tags, strings.Split(extraTags, ",")...)
	}
	if debugEnabled {
		tags = append(tags, debugTags...)
	}
	tags = common.Uniq(common.Filter(tags, func(it string) bool {
		return it != ""
	}))

	var archList []androidArch
	if platform != "" {
		// e.g. android/arm64
		goArch := platform[strings.LastIndex(platform, "/")+1:]
		for _, arch := range androidArchList {
			if arch.goArch == goArch {
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

	// Symbols are kept (callers strip with llvm-strip).
	ldFlags := debugFlags
	if versionOverride != "" {
		ldFlags = []string{"-ldflags", build_shared.LinkerFlags(versionOverride, true)}
	}

	for _, arch := range archList {
		outputName := "sing-box-android-" + arch.abi
		log.Info("building ", outputName, " (GOARCH=", arch.goArch, ", tags=", strings.Join(tags, ","), ")")

		cc := filepath.Join(ndkBin, arch.clang+androidAPI+"-clang")
		cxx := filepath.Join(ndkBin, arch.clang+androidAPI+"-clang++")
		if runtime.GOOS == "windows" {
			// The NDK's .cmd wrappers run through cmd.exe, whose 8191 character
			// command line limit the cronet link line exceeds; call clang
			// directly with the target the wrappers would add.
			target := " --target=" + arch.clang + androidAPI
			cc = "\"" + filepath.Join(ndkBin, "clang.exe") + "\"" + target
			cxx = "\"" + filepath.Join(ndkBin, "clang++.exe") + "\"" + target
		}

		args := []string{
			"build",
			"-buildmode=pie",
			"-v",
			"-trimpath",
			"-buildvcs=false",
		}
		args = append(args, ldFlags...)
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
			log.Fatal(E.Cause(err, "build ", outputName))
		}
		log.Info("built ", outputName)
	}
}
