// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package module

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/DataDog/datadog-agent/cmd/system-probe/api/module"
	sysconfigtypes "github.com/DataDog/datadog-agent/cmd/system-probe/config/types"
	"github.com/DataDog/datadog-agent/cmd/system-probe/utils"
	"github.com/DataDog/datadog-agent/comp/core/telemetry"
	workloadmeta "github.com/DataDog/datadog-agent/comp/core/workloadmeta/def"
	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/servicediscovery/model"
	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/servicediscovery/portlist"
	"github.com/DataDog/datadog-agent/pkg/util/kernel"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/DataDog/datadog-agent/pkg/util/optional"
	"github.com/gorilla/mux"
	"github.com/prometheus/procfs"
	"github.com/shirou/gopsutil/v3/process"
	"github.com/vishvananda/netns"
)

const (
	pathOpenPorts = "/open_ports"
	pathGetProc   = "/procs/{pid}"
)

// Ensure discovery implements the module.Module interface.
var _ module.Module = &discovery{}

// discovery is an implementation of the Module interface for the discovery module.
type discovery struct {
	portPoller *portlist.Poller
}

// NewDiscoveryModule creates a new discovery system probe module.
func NewDiscoveryModule(*sysconfigtypes.Config, optional.Option[workloadmeta.Component], telemetry.Component) (module.Module, error) {
	poller, err := portlist.NewPoller()
	if err != nil {
		return nil, err
	}
	return &discovery{portPoller: poller}, nil
}

// GetStats returns the stats of the discovery module.
func (s *discovery) GetStats() map[string]interface{} {
	return nil
}

// Register registers the discovery module with the provided HTTP mux.
func (s *discovery) Register(httpMux *module.Router) error {
	httpMux.HandleFunc("/status", s.handleStatusEndpoint)
	httpMux.HandleFunc(pathOpenPorts, s.handleOpenPorts)
	httpMux.HandleFunc(pathGetProc, s.handleGetProc)
	httpMux.HandleFunc("/processes", s.handleProcessesEndpoint)
	return nil
}

// Close cleans resources used by the discovery module.
// Currently, a no-op.
func (s *discovery) Close() {}

// handleStatusEndpoint is the handler for the /status endpoint.
// Reports the status of the discovery module.
func (s *discovery) handleStatusEndpoint(w http.ResponseWriter, _ *http.Request) {
	_, _ = w.Write([]byte("Discovery Module is running"))
}

func (s *discovery) handleError(w http.ResponseWriter, route string, status int, err error) {
	_ = log.Errorf("failed to handle /discovery/%s (status: %d): %v", route, status, err)
	w.WriteHeader(status)
}

func (s *discovery) handleOpenPorts(w http.ResponseWriter, _ *http.Request) {
	listeners, err := getListeners()
	if err != nil {
		_ = log.Errorf("Error", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// ports, err := s.portPoller.OpenPorts()
	// if err != nil {
	// 	s.handleError(w, pathOpenPorts, http.StatusInternalServerError, fmt.Errorf("failed to get open ports: %v", err))
	// 	return
	// }

	var portsResp []*model.Port
	for _, listener := range *listeners {
		for _, port := range listener.Ports {
			portsResp = append(portsResp, &model.Port{
				PID:         listener.Pid,
				ProcessName: listener.Name,
				Port:        int(port),
				Proto:       "tcp",
			})
		}
	}
	resp := &model.OpenPortsResponse{
		Ports: portsResp,
	}
	utils.WriteAsJSON(w, resp)
}

var allowedEnvironmentVariables = map[string]struct{}{
	"PATH":                     {},
	"PWD":                      {},
	"GUNICORN_CMD_ARGS":        {},
	"WSGI_APP":                 {},
	"DD_SERVICE":               {},
	"DD_TAGS":                  {},
	"DD_INJECTION_ENABLED":     {},
	"SPRING_APPLICATION_NAME":  {},
	"SPRING_CONFIG_LOCATIONS":  {},
	"SPRING_CONFIG_NAME":       {},
	"SPRING_PROFILES_ACTIVE":   {},
	"CORECLR_PROFILER_PATH":    {},
	"CORECLR_ENABLE_PROFILING": {},
	"JAVA_TOOL_OPTIONS":        {},
	"_JAVA_OPTIONS":            {},
	"JDK_JAVA_OPTIONS":         {},
	"JAVA_OPTIONS":             {},
	"CATALINA_OPTS":            {},
	"JDPA_OPTS":                {},
	"VIRTUAL_ENV":              {},
}

func filterEnv(in []string) (out []string) {
	for _, env := range in {
		split := strings.SplitN(env, "=", 2)
		if len(split) != 2 {
			continue
		}

		name := split[0]
		if _, ok := allowedEnvironmentVariables[name]; ok {
			out = append(out, env)
		}
	}
	return
}

func (s *discovery) handleGetProc(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	pidStr := vars["pid"]
	pid, err := strconv.ParseUint(pidStr, 10, 32)
	if err != nil {
		s.handleError(w, pathGetProc, http.StatusBadRequest, fmt.Errorf("failed to convert pid to integer: %v", err))
		return
	}

	if _, err := os.Stat(path.Join(procfs.DefaultMountPoint, pidStr)); os.IsNotExist(err) {
		s.handleError(w, pathGetProc, http.StatusNotFound, fmt.Errorf("/proc/{pid} does not exist: %v", err))
		return
	}
	proc, err := procfs.NewProc(int(pid))
	if err != nil {
		s.handleError(w, pathGetProc, http.StatusInternalServerError, fmt.Errorf("failed to read procfs: %v", err))
		return
	}
	env, err := proc.Environ()
	if err != nil {
		s.handleError(w, pathGetProc, http.StatusInternalServerError, fmt.Errorf("failed to read /proc/{pid}/environ: %v", err))
		return
	}
	cwd, err := proc.Cwd()
	if err != nil {
		s.handleError(w, pathGetProc, http.StatusInternalServerError, fmt.Errorf("failed to read /proc/{pid}/cwd: %v", err))
		return
	}

	resp := &model.GetProcResponse{
		Proc: &model.Proc{
			PID:     int(pid),
			Environ: filterEnv(env),
			CWD:     cwd,
		},
	}
	utils.WriteAsJSON(w, resp)
}

func getSockets(p *process.Process) ([]uint64, error) {
	// list all the file descriptors opened by the process
	FDs, err := p.OpenFiles()
	if err != nil {
		return nil, err
	}

	// sockets have the following pattern "socket:[inode]"
	var sockets []uint64
	for _, fd := range FDs {
		if strings.HasPrefix(fd.Path, "socket:[") {
			sock, err := strconv.Atoi(strings.TrimPrefix(fd.Path[:len(fd.Path)-1], "socket:["))
			if err != nil {
				continue
			}
			if sock < 0 {
				continue
			}
			sockets = append(sockets, uint64(sock))
		}
	}
	if len(sockets) <= 0 {
		return nil, nil
	}

	return sockets, nil
}

type NetNamespaceInfo struct {
	socketInodeToPort map[uint64]int
	addrs             []string
}

const (
	tcpListen uint64 = 10

	// tcpClose is also used to indicate a UDP connection where the other end hasn't been established
	tcpClose  uint64 = 7
	udpListen        = tcpClose
)

func getNsInfo(pid int) (*NetNamespaceInfo, error) {
	path := filepath.Join(kernel.HostProc(fmt.Sprintf("%d", pid)))
	proc, err := procfs.NewFS(path)
	if err != nil {
		log.Warnf("error while opening procfs (pid: %v): %s", pid, err)
		return nil, err
	}

	// looking for AF_INET sockets
	TCP, err := proc.NetTCP()
	if err != nil {
		log.Debugf("couldn't snapshot TCP sockets: %v", err)
	}
	UDP, err := proc.NetUDP()
	if err != nil {
		log.Debugf("couldn't snapshot UDP sockets: %v", err)
	}
	// looking for AF_INET6 sockets
	TCP6, err := proc.NetTCP6()
	if err != nil {
		log.Debugf("couldn't snapshot TCP6 sockets: %v", err)
	}
	UDP6, err := proc.NetUDP6()
	if err != nil {
		log.Debugf("couldn't snapshot UDP6 sockets: %v", err)
	}

	nsInfo := NetNamespaceInfo{
		socketInodeToPort: make(map[uint64]int),
	}

	ns, err := netns.GetFromPath(filepath.Join(path, "ns/net"))
	if err != nil {
		return nil, err
	}
	defer ns.Close()

	err = kernel.WithNS(ns, func() error {
		addrs, err := net.InterfaceAddrs()
		if err != nil {
			return nil
		}
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil {
					nsInfo.addrs = append(nsInfo.addrs, ipnet.IP.String())
				}
			}
		}
		return err
	})
	if err != nil {
		return nil, err
	}

	for _, sock := range TCP {
		if sock.St != tcpListen {
			continue
		}
		nsInfo.socketInodeToPort[sock.Inode] = int(sock.LocalPort)
	}
	for _, sock := range TCP6 {
		if sock.St != tcpListen {
			continue
		}
		nsInfo.socketInodeToPort[sock.Inode] = int(sock.LocalPort)
	}
	for _, sock := range UDP {
		if sock.St != udpListen {
			continue
		}
		nsInfo.socketInodeToPort[sock.Inode] = int(sock.LocalPort)
	}
	for _, sock := range UDP6 {
		if sock.St != udpListen {
			continue
		}
		nsInfo.socketInodeToPort[sock.Inode] = int(sock.LocalPort)
	}

	return &nsInfo, nil
}

type ContainerAddr struct {
	Ip   string
	Port int
}

func extractDockerProxy(cmd []string) (*ContainerAddr, int) {
	// Extract proxy target address
	containerAddr := &ContainerAddr{}
	hostPort := 0
	for i := 0; i < len(cmd)-1; i++ {
		switch cmd[i] {
		case "-container-ip":
			containerAddr.Ip = cmd[i+1]
		case "-container-port":
			port, err := strconv.ParseInt(cmd[i+1], 10, 32)
			if err != nil {
				return nil, 0
			}
			containerAddr.Port = int(port)
		case "-host-port":
			port, err := strconv.ParseInt(cmd[i+1], 10, 32)
			if err != nil {
				return nil, 0
			}
			hostPort = int(port)
		}
	}

	if containerAddr.Ip == "" || containerAddr.Port == 0 || hostPort == 0 {
		return nil, 0
	}

	return containerAddr, hostPort
}

func getListeners() (*[]model.Listener, error) {
	procRoot := kernel.ProcFSRoot()
	pids, err := process.Pids()
	if err != nil {
		return nil, err
	}

	var listeners []model.Listener
	netNsInfo := make(map[uint32]*NetNamespaceInfo)

	proxiedAddresses := make(map[ContainerAddr]int)

	rootNs, err := kernel.GetRootNetNamespace(procRoot)
	if err != nil {
		return nil, err
	}
	rootNsInode, err := kernel.GetInoForNs(rootNs)
	if err != nil {
		return nil, err
	}
	rootNs.Close()

	for _, pid := range pids {
		proc, err := process.NewProcess(pid)
		if err != nil {
			continue
		}

		ns, err := kernel.GetNetNsInoFromPid(procRoot, int(pid))
		if err != nil {
			return nil, nil
		}

		name, err := proc.Name()
		if err != nil {
			continue
		}

		cmdline, err := proc.Cmdline()
		if err != nil {
			continue
		}

		if name == "docker-proxy" {
			containerAddr, hostIp := extractDockerProxy(strings.Split(cmdline, " "))
			if containerAddr == nil {
				continue
			}

			proxiedAddresses[*containerAddr] = hostIp
			continue
		}

		listener := model.Listener{
			Pid:       int(pid),
			Namespace: int(ns),
			Name:      name,
			Cmdline:   cmdline,
		}

		nsInfo, ok := netNsInfo[ns]
		if !ok {
			nsInfo, err = getNsInfo(int(pid))
			if err != nil {
				continue
			}

			if ns == rootNsInode {
				nsInfo.addrs = []string{}
			}
			netNsInfo[ns] = nsInfo
		}

		sockets, err := getSockets(proc)
		if err != nil {
			continue
		}

		seenPorts := make(map[int]struct{})
		for _, socket := range sockets {
			if port, ok := nsInfo.socketInodeToPort[socket]; ok {
				if _, seen := seenPorts[port]; seen {
					continue
				}

				seenPorts[port] = struct{}{}
				listener.Ports = append(listener.Ports, port)
			}
		}

		if len(listener.Ports) == 0 {
			continue
		}

		listeners = append(listeners, listener)
	}

	var finalListeners []model.Listener
	for _, listener := range listeners {
		if listener.Namespace == int(rootNsInode) {
			finalListeners = append(finalListeners, listener)
		}

		var newPorts []int
		for _, port := range listener.Ports {
			for _, ip := range netNsInfo[uint32(listener.Namespace)].addrs {
				key := ContainerAddr{Ip: ip, Port: port}
				if newPort, ok := proxiedAddresses[key]; ok {
					newPorts = append(newPorts, newPort)
				}
			}
		}

		if len(newPorts) == 0 {
			// no proxy, hope for the best
			finalListeners = append(finalListeners, listener)
			continue
		}

		listener.Ports = newPorts
		finalListeners = append(finalListeners, listener)
	}

	return &finalListeners, nil
}

func (s *discovery) handleProcessesEndpoint(w http.ResponseWriter, _ *http.Request) {
	listeners, err := getListeners()
	if err != nil {
		_ = log.Errorf("Error", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	utils.WriteAsJSON(w, *listeners)
}
