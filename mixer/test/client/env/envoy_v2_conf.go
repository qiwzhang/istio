// Copyright 2018 Istio Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package env

import (
	"fmt"
	"io/ioutil"
	"log"

	"github.com/envoyproxy/go-control-plane/envoy/api/v2"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/listener"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/route"
	bootstrap "github.com/envoyproxy/go-control-plane/envoy/config/bootstrap/v2"
	accesslog "github.com/envoyproxy/go-control-plane/envoy/config/filter/accesslog/v2"
	hcm "github.com/envoyproxy/go-control-plane/envoy/config/filter/network/http_connection_manager/v2"
	"github.com/envoyproxy/go-control-plane/pkg/util"
	"github.com/ghodss/yaml"
	"github.com/gogo/protobuf/jsonpb"
	"github.com/gogo/protobuf/proto"
	"github.com/gogo/protobuf/types"
)

const (
	BackendClusterName     = "backend_cluster"
	ServerProxyClusterName = "server_proxy_cluster"
)

func toYAML(config proto.Message) ([]byte, error) {
	marshaler := jsonpb.Marshaler{OrigName: true}
	out, err := marshaler.MarshalToString(config)
	if err != nil {
		return nil, err
	}
	content, err := yaml.JSONToYAML([]byte(out))
	return content, nil
}

func toAddress(port uint16) *core.Address {
	return &core.Address{
		Address: &core.Address_SocketAddress{
			SocketAddress: &core.SocketAddress{
				Address:       "127.0.0.1",
				PortSpecifier: &core.SocketAddress_PortValue{PortValue: uint32(port)},
			},
		},
	}
}

func toStruct(msg proto.Message) *types.Struct {
	out, err := util.MessageToStruct(msg)
	if err != nil {
		panic(err)
	}
	return out
}

func (s *TestSetup) createEnvoyV2Conf(path string) error {
	config := s.createBoostrap()
	content, err := toYAML(config)
	if err != nil {
		return err
	}
	log.Printf("Static config:\n%s", string(content))
	return ioutil.WriteFile(path, content, 0644)
}

func (s *TestSetup) createBoostrap() *bootstrap.Bootstrap {
	return &bootstrap.Bootstrap{
		Admin: bootstrap.Admin{
			AccessLogPath: "/dev/stdout",
			Address:       toAddress(s.ports.AdminPort),
		},
		StaticResources: &bootstrap.Bootstrap_StaticResources{
			Listeners: s.createListeners(),
			Clusters:  s.createClusters(),
		},
	}
}

type httpListenerOptions struct {
	ListenerPort uint16
	ClusterName  string
	MixerConfig  *types.Struct
}

func (s *TestSetup) createListeners() []v2.Listener {
	out := make([]v2.Listener, 0, 3)

	// Create server proxy to backend service.
	out = append(out, s.createHttpListener(httpListenerOptions{
		ListenerPort: s.ports.ServerProxyPort,
		ClusterName:  BackendClusterName,
		MixerConfig:  toStruct(s.mfConf.HTTPServerConf),
	}))

	// create client proxy to server proxy.
	out = append(out, s.createHttpListener(httpListenerOptions{
		ListenerPort: s.ports.ClientProxyPort,
		ClusterName:  ServerProxyClusterName,
		MixerConfig:  toStruct(s.mfConf.HTTPClientConf),
	}))

	out = append(out, s.createTcpListener())
	return out
}

func (s *TestSetup) createHttpListener(options httpListenerOptions) *v2.Listener {
	hcm_config := &hcm.HttpConnectionManager{
		CodecType:  hcm.AUTO,
		StatPrefix: "ingress_proxy",
		AccessLog: []*accesslog.AccessLog{{
			Name: util.FileAccessLog,
			Config: toStruct(&accesslog.FileAccessLog{
				Path: "/dev/stdout",
			}),
		}},
		HttpFilters: []*hcm.HttpFilter{
			{
				Name:   "mixer",
				Config: options.MixerConfig,
			},
			{
				Name: util.Router,
			},
		},
		RouteSpecifier: &hcm.HttpConnectionManager_RouteConfig{
			RouteConfig: &v2.RouteConfiguration{
				VirtualHosts: []route.VirtualHost{{
					Name:    "backend",
					Domains: []string{"*"},
					Routes: []route.Route{{
						Match: route.RouteMatch{
							PathSpecifier: &route.RouteMatch_Prefix{
								Prefix: "/",
							},
						},
						Action: &route.Route_Route{
							Route: &route.RouteAction{
								ClusterSpecifier: &route.RouteAction_Cluster{Cluster: options.ClusterName},
							},
						},
					}},
				}},
			},
		},
	}

	return &v2.Listener{
		Address: toAddress(options.ListenerPort),
		Name:    fmt.Sprintf("Listener%d", options.ListenerPort),
		FilterChains: []listener.FilterChain{{
			Filters: []listener.Filter{{
				Name:   util.HTTPConnectionManager,
				Config: toStruct(hcm_config),
			}},
		}},
	}
}

func (s *TestSetup) createTcpListener() *v2.Listener {
	config := &tcp_proxy.TcpProxy{
		StatPrefix: "tcp",
		Cluster:    ServerProxyClusterName,
	}

	return &v2.Listener{
		Address: toAddress(s.ports.TCPProxyPort),
		Name:    "tcp_listener",
		FilterChains: []listener.FilterChain{{
			Filters: []listener.Filter{{
				Name:   "mixer",
				Config: toStruct(s.mfConf.TCPServerConf),
			},
				{
					Name:   xdsutil.TCPProxy,
					Config: toStruct(config),
				}},
		}},
	}
}

func (s *TestSetup) createClusters() []v2.Cluster {
	out := make([]v2.Cluster, 0, 3)
	out = append(out, createBackendCluster())
	out = append(out, createServerProxyCluster())
	out = append(out, createMixerServerCluster())
	return out
}

func (s *TestSetup) createDefaultCluster() *v2.Cluster {
	return &v2.Cluster{
		ConnectTimeout: 5 * time.Second,
		Type:           v2.Cluster_STRICT_DNS,
		LbPolicy:       v2.Cluster_ROUND_ROBIN,
	}
}

func (s *TestSetup) createBackendCluster() *v2.Cluster {
	c := createDefaultCluster()
	c.Name = BackendClusterName
	c.Hosts = []*core.Address{{toAddress(s.ports.BackendPort)}}
	return c
}

func (s *TestSetup) createServerProxyCluster() *v2.Cluster {
	c := createDefaultCluster()
	c.Name = ServerProxyClusterName
	c.Hosts = []*core.Address{{toAddress(s.ports.ServerProxyPort)}}
	return c
}

func (s *TestSetup) createMixerServerCluster() *v2.Cluster {
	c := createDefaultCluster()
	c.Name = "mixer_server"
	c.Hosts = []*core.Address{{toAddress(s.port.MixerPort)}}
	return c
}
