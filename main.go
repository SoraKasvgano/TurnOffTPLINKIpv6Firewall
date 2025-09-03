package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// 新增 DmzEnable 字段，用于控制DMZ的启用状态
type Config struct {
	RouterIP           string `json:"router_ip"`
	Stok               string `json:"stok"`
	IPv6FirewallEnable string `json:"ipv6_firewall_enable"`
	DmzDestIP          string `json:"dmz_dest_ip"`
	DmzDestIP6         string `json:"dmz_dest_ip6"`
	ServerPort         string `json:"server_port"`
	DmzEnable          string `json:"dmz_enable"` // 新增：DMZ启用状态 0=关闭 1=启用
}

var config Config

func readConfig(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		// 配置文件不存在时，设置默认值
		config.ServerPort = "8080"
		config.DmzEnable = "1" // 默认启用DMZ
		return err
	}
	defer file.Close()

	bytes, err := ioutil.ReadAll(file)
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

func sendRequest() (bool, string) {
	requestBody := map[string]interface{}{
		"firewall": map[string]interface{}{
			"dmz": map[string]interface{}{
				"enable":   config.DmzEnable, // 使用配置的DMZ启用状态
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

	responseBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Sprintf("读取响应错误: %v", err)
	}

	return resp.StatusCode == 200, string(responseBody)
}

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

		// 处理DMZ启用状态（新增）
		dmzEnable := r.FormValue("dmz_enable")
		if dmzEnable == "0" || dmzEnable == "1" {
			config.DmzEnable = dmzEnable
		} else {
			// 如果输入无效，保持当前配置的值
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

	// 在网页表单中添加DMZ启用状态的设置项
	tmpl := `<html>
		<body>
			<form method="post">
				<label>Router IP:</label><br>
				<input type="text" name="router_ip" placeholder="例如: 192.168.0.1" value="{{.RouterIP}}"><br>
				
				<label>Stok:</label><br>
				<input type="text" name="stok" placeholder="路由器认证令牌" value="{{.Stok}}"><br>
				
				<label>IPv6 Firewall Enable (on=开启,off=关闭):</label><br>
				<input type="text" name="ipv6_firewall_enable" placeholder="on或off" value="{{.IPv6FirewallEnable}}"><br>
				
				<label>DMZ 启用状态 (1=启用,0=关闭):</label><br> <!-- 新增 -->
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
	// 将当前配置传递给模板，实现表单值回显
	t.Execute(w, config)
}

func successHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "操作成功！可关闭浏览器返回程序，按回车退出。")
}

func openBrowser(url string) error {
	switch runtime.GOOS {
	case "windows":
		return exec.Command("cmd", "/c", "start", url).Start()
	default:
		return fmt.Errorf("不支持的操作系统: %s", runtime.GOOS)
	}
}

func main() {
	if err := readConfig("config.json"); err != nil {
		fmt.Println("读取配置文件错误:", err)
		fmt.Println("将允许通过网页输入配置，服务器使用默认端口 8080...")
	}

	http.HandleFunc("/", handler)
	http.HandleFunc("/success", successHandler)

	go func() {
		serverAddr := fmt.Sprintf(":%s", config.ServerPort)
		serverURL := fmt.Sprintf("http://localhost:%s", config.ServerPort)

		fmt.Printf("服务器启动，访问 %s\n", serverURL)

		if err := openBrowser(serverURL); err != nil {
			fmt.Printf("自动打开浏览器失败，请手动访问: %s\n错误原因: %v\n", serverURL, err)
		} else {
			fmt.Println("已自动打开默认浏览器，若未弹出请手动访问上述地址")
		}

		err := http.ListenAndServe(serverAddr, nil)
		if err != nil {
			fmt.Printf("服务器错误: %v\n", err)
			fmt.Printf("提示：端口 %s 可能已被占用，请修改 config.json 中的 server_port 字段（如 8081）\n", config.ServerPort)
		}
	}()

	fmt.Println("按回车键关闭程序...")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()

	fmt.Println("程序正在关闭...")
	os.Exit(0)
}
