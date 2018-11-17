package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/go-apibox/config"
	"github.com/go-apibox/web"
)

var spiderExp *regexp.Regexp

func init() {
	spiderExp, _ = regexp.Compile(`(?i)baiduspider|googlebot|soso|bing|sogou|yahoo|sohu-search|yodao|YoudaoBot|robozilla|msnbot|MJ12bot|NHN|Twiceler|Mozilla/4.0`)
}

func main() {
	var configFile string
	flag.StringVar(&configFile, "c", "config.yaml", "yaml config file")
	flag.Parse()

	wd, err := os.Getwd()
	if err != nil {
		logger.Fatalf(err.Error())
	}
	if !filepath.IsAbs(configFile) {
		configFile = filepath.Join(wd, configFile)
	}

	cfg, err := config.FromFile(configFile)
	if err != nil {
		logger.Fatalf(err.Error())
	}

	webRoot := filepath.Dir(configFile)
	webConfig := web.NewConfig(cfg)

	// 处理web配置
	mainHost := cfg.GetDefaultString("app.host", "")
	w, err := web.FromConfig(webRoot, mainHost, webConfig)
	if err != nil {
		logger.Fatalf(err.Error())
	}

	sessionDomain := cfg.GetDefaultString("app.session.domain", "")
	if sessionDomain != "" {
		w.SetSessionDomain(sessionDomain)
	}

	webHander := w.Handler()

	mainAddr := cfg.GetDefaultString("app.http_addr", ":80")
	logger.Info("listening on %s, host: %s", mainAddr, mainHost)

	tlsEnabled := cfg.GetDefaultBool("app.tls.enabled", false)

	mirrorHosts := cfg.GetDefaultStringArray("app.mirror_hosts", []string{})
	if len(mirrorHosts) > 0 {
		var protocol string
		if tlsEnabled {
			protocol = "https"
		} else {
			protocol = "http"
		}
		port := mainAddr[strings.IndexByte(mainAddr, ':')+1:]
		mainUrl := fmt.Sprintf("%s://%s:%s", protocol, mainHost, port)

		// 其它镜像主机的访问自动跳转到主地址
		mirrorHostMap := make(map[string][]HostDefine)
		for _, mirrorHost := range mirrorHosts {
			parts := strings.Split(mirrorHost, "|")
			var tFlag string
			if len(parts) != 2 && len(parts) != 3 {
				continue
			}
			tHost, tAddr := parts[0], parts[1]
			if len(parts) == 3 {
				tFlag = parts[2]
			}

			if _, has := mirrorHostMap[tAddr]; has {
				mirrorHostMap[tAddr] = append(mirrorHostMap[tAddr], HostDefine{tHost, tFlag})
			} else {
				mirrorHostMap[tAddr] = []HostDefine{{tHost, tFlag}}
			}
		}

		for tAddr, tHosts := range mirrorHostMap {
			if tAddr == mainAddr {
				// 与主站监听同一个地址
				webHander = wrapMultiHostServer(mainUrl, tHosts, webHander)
				continue
			}

			// 不同监听地址，需要额外监听
			go func(mainUrl string, addr string, aliasHosts []HostDefine) {
				hostMap := make(map[string]HostDefine, len(aliasHosts))
				for _, tHost := range aliasHosts {
					hostMap[tHost.Host] = tHost
				}

				mux := http.NewServeMux()
				mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
					if tHost, has := hostMap[r.Host]; has {
						if tHost.Flag == "spider" {
							// 判断是否是爬虫请求
							if spiderExp.MatchString(r.UserAgent()) {
								webHander.ServeHTTP(w, r)
								return
							}
						}
						http.Redirect(w, r, mainUrl+r.RequestURI, 301)
						return
					}
					http.NotFound(w, r)
				})

				logger.Info("listening on %s, host: %v", addr, aliasHosts)
				err := http.ListenAndServe(addr, mux)
				if err != nil {
					logger.Fatalf(err.Error())
				}
			}(mainUrl, tAddr, tHosts)
		}
	}

	http.Handle(webConfig.GetBaseUrl(), webHander)

	if tlsEnabled {
		certFile := cfg.GetDefaultString("app.tls.cert", "server.crt")
		keyFile := cfg.GetDefaultString("app.tls.key", "server.key")

		var certPemBlock, keyPemBlock []byte
		var err error
		var autoGenCert bool

		if certFile != "" && keyFile != "" {
			// SSL证书文件的相对路径为相对于配置文件的路径
			if !filepath.IsAbs(certFile) {
				certFile = filepath.Join(webRoot, certFile)
			}
			if !filepath.IsAbs(keyFile) {
				keyFile = filepath.Join(webRoot, keyFile)
			}

			certPemBlock, keyPemBlock, err = loadX509PemBlock(certFile, keyFile)
			if err != nil {
				// 解析失败，不停止服务，转而使用自动生成证书
				logger.Error(err.Error())
				autoGenCert = true
			} else {
				autoGenCert = false
			}
		} else {
			autoGenCert = true
		}

		if autoGenCert {
			// 自动生成证书
			bindIp := mainAddr[0:strings.IndexByte(mainAddr, ':')]
			certPemBlock, keyPemBlock, err = makeCert(mainHost, bindIp)
			if err != nil {
				logger.Fatalf(err.Error())
			}
		}

		err = listenAndServeTLS(mainAddr, certPemBlock, keyPemBlock, nil)
		if err != nil {
			logger.Fatalf(err.Error())
		}
	} else {
		err = http.ListenAndServe(mainAddr, nil)
		if err != nil {
			logger.Fatalf(err.Error())
		}
	}
}

type HostDefine struct {
	Host string
	Flag string
}

// 域名别名处理，所有别名都会跳转到指定域名
type aliasHostHandler struct {
	mainUrl      string
	aliasHostMap map[string]HostDefine
	oldHandler   http.Handler
}

func wrapMultiHostServer(mainUrl string, aliasHosts []HostDefine, oldHandler http.Handler) http.Handler {
	aliasHostMap := make(map[string]HostDefine, len(aliasHosts))
	for _, aliasHost := range aliasHosts {
		aliasHostMap[aliasHost.Host] = aliasHost
	}

	logger.Info("listening on main addr, host: %v", aliasHosts)

	return &aliasHostHandler{mainUrl, aliasHostMap, oldHandler}
}

func (a *aliasHostHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if aliasHost, has := a.aliasHostMap[r.Host]; has {
		if aliasHost.Flag == "spider" {
			// 判断是否是爬虫请求
			if spiderExp.MatchString(r.UserAgent()) {
				a.oldHandler.ServeHTTP(w, r)
				return
			}
		}
		http.Redirect(w, r, a.mainUrl+r.RequestURI, 301)
	} else {
		a.oldHandler.ServeHTTP(w, r)
	}
}
