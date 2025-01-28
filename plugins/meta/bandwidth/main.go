// Copyright 2018 CNI authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"encoding/json"
	"fmt"

	"github.com/vishvananda/netlink"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"

	bw "github.com/containernetworking/plugins/pkg/bandwidth"
	"github.com/containernetworking/plugins/pkg/ns"
	bv "github.com/containernetworking/plugins/pkg/utils/buildversion"
)

const (
	defaultQdiscType = "ingress"
)

// parseConfig parses the supplied configuration (and prevResult) from stdin.
func parseConfig(stdin []byte) (*bw.PluginConf, error) {
	conf := bw.PluginConf{}

	if err := json.Unmarshal(stdin, &conf); err != nil {
		return nil, fmt.Errorf("failed to parse network configuration: %v", err)
	}

	bandwidth := bw.GetBandwidth(&conf)
	if bandwidth != nil {
		err := bw.ValidateRateAndBurst(bandwidth.IngressRate, bandwidth.IngressBurst)
		if err != nil {
			return nil, err
		}
		err = bw.ValidateRateAndBurst(bandwidth.EgressRate, bandwidth.EgressBurst)
		if err != nil {
			return nil, err
		}
	}

	if conf.RawPrevResult != nil {
		var err error
		if err = version.ParsePrevResult(&conf.NetConf); err != nil {
			return nil, fmt.Errorf("could not parse prevResult: %v", err)
		}

		_, err = current.NewResultFromResult(conf.PrevResult)
		if err != nil {
			return nil, fmt.Errorf("could not convert result to current version: %v", err)
		}
	}

	return &conf, nil

}

func cmdAdd(args *skel.CmdArgs) error {
	conf, err := parseConfig(args.StdinData)
	if err != nil {
		return err
	}

	bandwidth := bw.GetBandwidth(conf)
	if bandwidth == nil || bandwidth.IsZero() {
		return types.PrintResult(conf.PrevResult, conf.CNIVersion)
	}

	if conf.PrevResult == nil {
		return fmt.Errorf("must be called as chained plugin")
	}

	result, err := current.NewResultFromResult(conf.PrevResult)
	if err != nil {
		return fmt.Errorf("could not convert result to current version: %v", err)
	}

	netns, err := ns.GetNS(args.Netns)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %v", netns, err)
	}
	defer netns.Close()

	hostInterface, err := bw.GetHostInterface(result.Interfaces, args.IfName, netns)
	if err != nil {
		return err
	}

	if bandwidth.IngressRate > 0 && bandwidth.IngressBurst > 0 {
		err = bw.CreateIngressQdisc(bandwidth.IngressRate, bandwidth.IngressBurst, hostInterface.Name)
		if err != nil {
			return err
		}
	}

	if bandwidth.EgressRate > 0 && bandwidth.EgressBurst > 0 {
		mtu, err := bw.GetMTU(hostInterface.Name)
		if err != nil {
			return err
		}

		ifbDeviceName := bw.GetIfbDeviceName(conf.Name, args.ContainerID)

		err = bw.CreateIfb(ifbDeviceName, mtu)
		if err != nil {
			return err
		}

		ifbDevice, err := netlink.LinkByName(ifbDeviceName)
		if err != nil {
			return err
		}

		result.Interfaces = append(result.Interfaces, &current.Interface{
			Name: ifbDeviceName,
			Mac:  ifbDevice.Attrs().HardwareAddr.String(),
		})
		err = bw.CreateEgressQdisc(defaultQdiscType, bandwidth.EgressRate, bandwidth.EgressBurst, hostInterface.Name, ifbDeviceName)
		if err != nil {
			return err
		}
	}

	return types.PrintResult(result, conf.CNIVersion)
}

func cmdDel(args *skel.CmdArgs) error {
	conf, err := parseConfig(args.StdinData)
	if err != nil {
		return err
	}

	ifbDeviceName := bw.GetIfbDeviceName(conf.Name, args.ContainerID)

	return bw.TeardownIfb(ifbDeviceName)
}

func main() {
	skel.PluginMain(cmdAdd, cmdCheck, cmdDel, version.VersionsStartingFrom("0.3.0"), bv.BuildString("bandwidth"))
}

func cmdCheck(args *skel.CmdArgs) error {
	bwConf, err := parseConfig(args.StdinData)
	if err != nil {
		return err
	}

	if bwConf.PrevResult == nil {
		return fmt.Errorf("must be called as a chained plugin")
	}

	result, err := current.NewResultFromResult(bwConf.PrevResult)
	if err != nil {
		return fmt.Errorf("could not convert result to current version: %v", err)
	}

	netns, err := ns.GetNS(args.Netns)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %v", netns, err)
	}
	defer netns.Close()

	hostInterface, err := bw.GetHostInterface(result.Interfaces, args.IfName, netns)
	if err != nil {
		return err
	}
	link, err := netlink.LinkByName(hostInterface.Name)
	if err != nil {
		return err
	}

	bandwidth := bw.GetBandwidth(bwConf)

	if bandwidth.IngressRate > 0 && bandwidth.IngressBurst > 0 {
		rateInBytes := bandwidth.IngressRate / 8
		burstInBytes := bandwidth.IngressBurst / 8
		bufferInBytes := bw.Buffer(rateInBytes, uint32(burstInBytes))
		latency := bw.LatencyInUsec(bw.LatencyInMillis)
		limitInBytes := bw.Limit(rateInBytes, latency, uint32(burstInBytes))

		qdiscs, err := bw.SafeQdiscList(link)
		if err != nil {
			return err
		}
		if len(qdiscs) == 0 {
			return fmt.Errorf("Failed to find qdisc")
		}

		for _, qdisc := range qdiscs {
			tbf, isTbf := qdisc.(*netlink.Tbf)
			if !isTbf {
				break
			}
			if tbf.Rate != uint64(rateInBytes) {
				return fmt.Errorf("Rate doesn't match")
			}
			if tbf.Limit != uint32(limitInBytes) {
				return fmt.Errorf("Limit doesn't match")
			}
			if tbf.Buffer != uint32(bufferInBytes) {
				return fmt.Errorf("Buffer doesn't match")
			}
		}
	}

	if bandwidth.EgressRate > 0 && bandwidth.EgressBurst > 0 {
		rateInBytes := bandwidth.EgressRate / 8
		burstInBytes := bandwidth.EgressBurst / 8
		bufferInBytes := bw.Buffer(rateInBytes, uint32(burstInBytes))
		latency := bw.LatencyInUsec(bw.LatencyInMillis)
		limitInBytes := bw.Limit(rateInBytes, latency, uint32(burstInBytes))

		ifbDeviceName := bw.GetIfbDeviceName(bwConf.Name, args.ContainerID)

		ifbDevice, err := netlink.LinkByName(ifbDeviceName)
		if err != nil {
			return fmt.Errorf("get ifb device: %s", err)
		}

		qdiscs, err := bw.SafeQdiscList(ifbDevice)
		if err != nil {
			return err
		}
		if len(qdiscs) == 0 {
			return fmt.Errorf("Failed to find qdisc")
		}

		for _, qdisc := range qdiscs {
			tbf, isTbf := qdisc.(*netlink.Tbf)
			if !isTbf {
				break
			}
			if tbf.Rate != uint64(rateInBytes) {
				return fmt.Errorf("Rate doesn't match")
			}
			if tbf.Limit != uint32(limitInBytes) {
				return fmt.Errorf("Limit doesn't match")
			}
			if tbf.Buffer != uint32(bufferInBytes) {
				return fmt.Errorf("Buffer doesn't match")
			}
		}
	}

	return nil
}
