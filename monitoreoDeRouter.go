package main

import (
	"crypto/sha256"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	routerIP   = "192.168.1.1"
	routerUser = "user"
	routerPass = "user"
	routerBase = "http://192.168.1.1"
)

var (
	client *http.Client

	// datos compartidos entre el monitor y el servidor web
	status     map[string]interface{}
	statusLock sync.RWMutex
)

type Device struct {
	MACAddress string
	IPAddress  string
	HostName   string
}

type DevicesInfo struct {
	XMLName xml.Name `xml:"ajax_response_xml_root"`
	Devices struct {
		Instance []struct {
			ParaName  []string `xml:"ParaName"`
			ParaValue []string `xml:"ParaValue"`
		} `xml:"Instance"`
	} `xml:"OBJ_WLAN_AD_ID"`
}

type LanDevicesInfo struct {
	XMLName xml.Name `xml:"ajax_response_xml_root"`
	Devices struct {
		Instance []struct {
			ParaName  []string `xml:"ParaName"`
			ParaValue []string `xml:"ParaValue"`
		} `xml:"Instance"`
	} `xml:"OBJ_ACCESSDEV_ID"`
}

func init() {
	jar, _ := cookiejar.New(nil)
	client = &http.Client{Jar: jar, Timeout: 10 * time.Second}
	status = map[string]interface{}{
		"online": false, "latency": 0, "packet_loss": 0,
		"sent": 0, "received": 0, "devices": []Device{},
		"last_update": "-",
	}
}

func getSessionToken() (string, error) {
	resp, err := client.Get(fmt.Sprintf("%s/?_type=loginData&_tag=login_entry", routerBase))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var data struct {
		SessionToken string `json:"sess_token"`
	}
	json.NewDecoder(resp.Body).Decode(&data)
	if data.SessionToken == "" {
		return "", fmt.Errorf("no session token")
	}
	return data.SessionToken, nil
}

func getLoginToken() (string, error) {
	resp, err := client.Get(fmt.Sprintf("%s/?_type=loginData&_tag=login_token&_=%d", routerBase, time.Now().UnixMilli()))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	token := strings.TrimLeft(strings.TrimRight(string(body), "</ajax_response_xml_root>"), "<ajax_response_xml_root>")
	if token == "" {
		return "", fmt.Errorf("no login token")
	}
	return token, nil
}

func login() error {
	sessionToken, err := getSessionToken()
	if err != nil {
		return err
	}
	loginToken, err := getLoginToken()
	if err != nil {
		return err
	}
	passHash := fmt.Sprintf("%x", sha256.Sum256([]byte(routerPass+loginToken)))
	data := url.Values{}
	data.Set("action", "login")
	data.Set("Password", passHash)
	data.Set("Username", routerUser)
	data.Set("_sessionTOKEN", sessionToken)
	resp, err := client.PostForm(fmt.Sprintf("%s/?_type=loginData&_tag=login_entry", routerBase), data)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var result struct {
		NeedRefresh bool   `json:"login_need_refresh"`
		ErrorMsg    string `json:"loginErrMsg"`
	}
	json.NewDecoder(resp.Body).Decode(&result)
	if !result.NeedRefresh {
		return fmt.Errorf("login failed: %s", result.ErrorMsg)
	}
	return nil
}

func getDevices(tag string) []Device {
	client.Get(fmt.Sprintf("%s/?_type=menuView&_tag=localNetStatus&_=%d", routerBase, time.Now().UnixMilli()))
	resp, err := client.Get(fmt.Sprintf("%s/?_type=menuData&_tag=%s&_=%d", routerBase, tag, time.Now().UnixMilli()))
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var devices []Device

	if tag == "wlan_client_stat_lua.lua" {
		var info DevicesInfo
		if xml.Unmarshal(body, &info) == nil {
			for _, inst := range info.Devices.Instance {
				d := parseInstance(inst)
				if d.MACAddress != "" {
					devices = append(devices, d)
				}
			}
		}
	} else {
		var info LanDevicesInfo
		if xml.Unmarshal(body, &info) == nil {
			for _, inst := range info.Devices.Instance {
				d := parseInstance(inst)
				if d.MACAddress != "" {
					devices = append(devices, d)
				}
			}
		}
	}
	return devices
}

func parseInstance(inst struct {
	ParaName  []string `xml:"ParaName"`
	ParaValue []string `xml:"ParaValue"`
}) Device {
	var d Device
	for i := range inst.ParaName {
		switch inst.ParaName[i] {
		case "MACAddress":
			d.MACAddress = strings.ToUpper(inst.ParaValue[i])
		case "IPAddress":
			d.IPAddress = inst.ParaValue[i]
		case "HostName":
			d.HostName = inst.ParaValue[i]
		}
	}
	return d
}

func getAllDevices() []Device {
	wifi := getDevices("wlan_client_stat_lua.lua")
	lan := getDevices("accessdev_landevs_lua.lua")
	seen := make(map[string]bool)
	var all []Device
	for _, d := range append(wifi, lan...) {
		if !seen[d.MACAddress] {
			seen[d.MACAddress] = true
			all = append(all, d)
		}
	}
	return all
}

func pingRouter() (bool, float64) {
	out, err := exec.Command("ping", "-c", "1", "-W", "1", routerIP).CombinedOutput()
	if err != nil {
		return false, 0
	}
	match := regexp.MustCompile(`time[=<](\d+\.?\d*)ms`).FindStringSubmatch(string(out))
	if len(match) >= 2 {
		ms, _ := strconv.ParseFloat(match[1], 64)
		return true, ms
	}
	return true, 0
}

// monitor: cada 10 segundos actualiza el estado
func monitorLoop() {
	sent := 0
	received := 0

	for {
		sent++
		online, latency := pingRouter()
		devices := []Device{}
		routerErr := ""

		if online {
			received++
			if err := login(); err != nil {
				routerErr = err.Error()
			} else {
				devices = getAllDevices()
			}
		}

		statusLock.Lock()
		status["online"] = online
		status["latency"] = latency
		status["sent"] = sent
		status["received"] = received
		status["packet_loss"] = fmt.Sprintf("%.1f", float64(sent-received)/float64(sent)*100)
		status["devices"] = devices
		status["device_count"] = len(devices)
		status["router_error"] = routerErr
		status["last_update"] = time.Now().Format("15:04:05")
		statusLock.Unlock()

		fmt.Printf("[%s] %s | %.0fms | %d dispositivos\n",
			time.Now().Format("15:04:05"),
			map[bool]string{true: "ONLINE", false: "OFFLINE"}[online],
			latency, len(devices))

		time.Sleep(10 * time.Second)
	}
}

// servidor web basico
func apiHandler(w http.ResponseWriter, r *http.Request) {
	statusLock.RLock()
	defer statusLock.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func main() {
	go monitorLoop()

	http.HandleFunc("/api", apiHandler)
	http.Handle("/", http.FileServer(http.Dir(".")))

	fmt.Println("===================================")
	fmt.Println("     MONITOR DEL ROUTER ZTE F6600")
	fmt.Println("===================================")
	fmt.Println("Router:", routerIP)
	fmt.Println("Abri http://localhost:8080 en el navegador")
	fmt.Println()

	http.ListenAndServe(":8080", nil)
}
