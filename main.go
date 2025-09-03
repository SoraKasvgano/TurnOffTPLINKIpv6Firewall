package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

// 配置结构
type Config struct {
	RouterIP           string `json:"router_ip"`
	Stok               string `json:"stok"`
	IPv6FirewallEnable string `json:"ipv6_firewall_enable"`
	DmzDestIP          string `json:"dmz_dest_ip"`
	DmzDestIP6         string `json:"dmz_dest_ip6"`
	ServerPort         string `json:"server_port"`
	DmzEnable          string `json:"dmz_enable"` // DMZ启用状态 0=关闭 1=启用
}

var (
	config       Config
	childProcess *os.Process // 跟踪子进程
	mu           sync.Mutex  // 确保进程操作线程安全
	processGroup int         // Windows进程组ID
)

// 读取配置文件
func readConfig(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		// 配置文件不存在时，设置默认值
		config.ServerPort = "8080"
		config.DmzEnable = "1" // 默认启用DMZ
		return err
	}
	defer file.Close()

	bytes, err := io.ReadAll(file)
	if err != nil {
		config.ServerPort = "8080"
		config.DmzEnable = "1"
		return err
	}

	// 解析前设置默认值，防止配置文件中未包含这些字段
	config.ServerPort = "8080"
	config.DmzEnable = "1"
	return json.Unmarshal(bytes, &config)
}

// 发送请求到路由器
func sendRequest() (bool, string) {
	requestBody := map[string]interface{}{
		"firewall": map[string]interface{}{
			"dmz": map[string]interface{}{
				"enable":   config.DmzEnable,
				"dest_ip":  config.DmzDestIP,
				"wan_port": "0",
				"dest_ip6": config.DmzDestIP6,
			},
			"ipv6_firewall": map[string]interface{}{
				"enable": config.IPv6FirewallEnable,
			},
		},
		"method": "set",
	}

	body, err := json.Marshal(requestBody)
	if err != nil {
		return false, fmt.Sprintf("错误: %v", err)
	}

	url := fmt.Sprintf("http://%s/stok=%s/ds", config.RouterIP, config.Stok)

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(body))
	if err != nil {
		return false, fmt.Sprintf("请求错误: %v", err)
	}
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Sprintf("读取响应错误: %v", err)
	}

	return resp.StatusCode == 200, string(responseBody)
}

// HTTP请求处理
func handler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		config.RouterIP = r.FormValue("router_ip")
		config.Stok = r.FormValue("stok")

		// 处理IPv6防火墙状态
		ipv6Firewall := strings.ToLower(r.FormValue("ipv6_firewall_enable"))
		switch ipv6Firewall {
		case "on":
			config.IPv6FirewallEnable = "on"
		case "off":
			config.IPv6FirewallEnable = "off"
		default:
			config.IPv6FirewallEnable = ipv6Firewall
		}

		// 处理DMZ启用状态
		dmzEnable := r.FormValue("dmz_enable")
		if dmzEnable == "0" || dmzEnable == "1" {
			config.DmzEnable = dmzEnable
		} else {
			fmt.Fprintf(w, "DMZ启用状态必须为0或1，已保持原有值: %s<br>", config.DmzEnable)
		}

		config.DmzDestIP = r.FormValue("dmz_dest_ip")
		config.DmzDestIP6 = r.FormValue("dmz_dest_ip6")

		success, message := sendRequest()
		if success {
			http.Redirect(w, r, "/success", http.StatusSeeOther)
		} else {
			fmt.Fprintf(w, "操作失败: %s", message)
		}
		return
	}

	// 网页表单模板
	tmpl := `<html>
		<body>
			<form method="post">
				<label>Router IP:</label><br>
				<input type="text" name="router_ip" placeholder="例如: 192.168.0.1" value="{{.RouterIP}}"><br>
				
				<label>Stok:</label><br>
				<input type="text" name="stok" placeholder="路由器认证令牌" value="{{.Stok}}"><br>
				
				<label>IPv6 Firewall Enable (on=开启,off=关闭):</label><br>
				<input type="text" name="ipv6_firewall_enable" placeholder="on或off" value="{{.IPv6FirewallEnable}}"><br>
				
				<label>DMZ 启用状态 (1=启用,0=关闭):</label><br>
				<input type="text" name="dmz_enable" placeholder="0或1" value="{{.DmzEnable}}"><br>
				
				<label>DMZ Destination IP (IPv4):</label><br>
				<input type="text" name="dmz_dest_ip" placeholder="例如: 192.168.0.102" value="{{.DmzDestIP}}"><br>
				
				<label>DMZ Destination IPv6:</label><br>
				<input type="text" name="dmz_dest_ip6" placeholder="例如: 240e:370:xx" value="{{.DmzDestIP6}}"><br>
				
				<input type="submit" value="提交">
			</form>
		</body>
	</html>`
	t, _ := template.New("form").Parse(tmpl)
	t.Execute(w, config)
}

// 成功页面处理
func successHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "操作成功！可关闭浏览器返回程序，按Enter退出。")
}

// 安全执行命令并跟踪进程组
func safeExecCommand(name string, args ...string) error {
	mu.Lock()
	defer mu.Unlock()

	// 先终止任何已存在的子进程和进程组
	cleanupProcesses()

	// 创建命令并配置进程组
	cmd := exec.Command(name, args...)

	// Windows特有的进程组设置
	if runtime.GOOS == "windows" {
		// 创建新的进程组
		cmd.SysProcAttr = &syscall.SysProcAttr{
			CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP,
		}
	}

	// 启动命令
	if err := cmd.Start(); err != nil {
		return err
	}

	// 保存进程引用
	childProcess = cmd.Process

	// Windows下获取进程组ID
	if runtime.GOOS == "windows" {
		processGroup = cmd.Process.Pid
	}

	// 启动goroutine监控进程，确保完成后清理引用
	go func() {
		cmd.Wait()
		mu.Lock()
		childProcess = nil
		processGroup = 0
		mu.Unlock()
	}()

	return nil
}

// 清理所有相关进程
func cleanupProcesses() {
	if childProcess != nil && childProcess.Pid > 0 {
		// 先尝试优雅关闭
		childProcess.Signal(os.Interrupt)

		// 等待1秒给进程退出时间
		time.Sleep(1 * time.Second)

		// 如果仍在运行，强制终止
		if err := childProcess.Signal(os.Kill); err != nil {
			fmt.Printf("警告: 无法终止进程 %d: %v\n", childProcess.Pid, err)
		}

		// Windows下特殊处理：终止整个进程组
		if runtime.GOOS == "windows" && processGroup > 0 {
			kernel32, err := syscall.LoadLibrary("kernel32.dll")
			if err == nil {
				defer syscall.FreeLibrary(kernel32)

				terminateProc, err := syscall.GetProcAddress(kernel32, "TerminateProcess")
				if err == nil {
					// 打开进程组
					handle, err := syscall.OpenProcess(syscall.PROCESS_TERMINATE, false, uint32(processGroup))
					if err == nil {
						defer syscall.CloseHandle(handle)

						// 终止进程组
						syscall.Syscall(terminateProc, 2, uintptr(handle), 0, 0)
					}
				}
			}
		}

		childProcess = nil
		processGroup = 0
	}
}

// 打开浏览器
func openBrowser(url string) error {
	switch runtime.GOOS {
	case "windows":
		// 使用start命令的/b参数不创建新窗口，减少进程残留
		return safeExecCommand("cmd", "/c", "start", "/b", url)
	default:
		return fmt.Errorf("不支持的操作系统: %s", runtime.GOOS)
	}
}

// 程序退出前的清理工作
func cleanup() {
	mu.Lock()
	defer mu.Unlock()
	cleanupProcesses()
}

func main() {
	// 注册程序退出时的清理函数
	defer cleanup()

	if err := readConfig("config.json"); err != nil {
		fmt.Println("读取配置文件错误:", err)
		fmt.Println("将允许通过网页输入配置，服务器使用默认端口 8080...")
	}

	http.HandleFunc("/", handler)
	http.HandleFunc("/success", successHandler)

	serverQuit := make(chan struct{})
	go func() {
		serverAddr := fmt.Sprintf(":%s", config.ServerPort)
		serverURL := fmt.Sprintf("http://localhost:%s", config.ServerPort)

		fmt.Printf("服务器启动，访问 %s\n", serverURL)

		if err := openBrowser(serverURL); err != nil {
			fmt.Printf("自动打开浏览器失败，请手动访问: %s\n错误原因: %v\n", serverURL, err)
		} else {
			fmt.Println("已自动打开默认浏览器，若未弹出请手动访问上述地址")
		}

		// 创建带关闭功能的服务器
		srv := &http.Server{Addr: serverAddr}
		go func() {
			<-serverQuit
			srv.Close()
		}()

		err := srv.ListenAndServe()
		if err != nil && !strings.Contains(err.Error(), "closed") {
			fmt.Printf("服务器错误: %v\n", err)
			fmt.Printf("提示：端口 %s 可能已被占用，请修改 config.json 中的 server_port 字段（如 8081）\n", config.ServerPort)
		}
	}()

	fmt.Println("按Enter键关闭程序...")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()

	fmt.Println("程序正在关闭...")
	close(serverQuit)
	// 给服务器关闭留出时间
	time.Sleep(500 * time.Millisecond)
	os.Exit(0)
}
